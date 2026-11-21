//go:build integration

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/types"
)

type staticApprovalLoader struct{ request *types.ApprovalRequest }

func (l staticApprovalLoader) Get(context.Context, string, string) (*types.ApprovalRequest, error) {
	return l.request, nil
}

type recordingDeploymentPlanApprovalHandler struct {
	revalidated []string
	linked      []string
	err         error
}

func (h *recordingDeploymentPlanApprovalHandler) RevalidateApprovedExecution(_ context.Context, _, planID, _ string) error {
	h.revalidated = append(h.revalidated, planID)
	return h.err
}

func (h *recordingDeploymentPlanApprovalHandler) LinkApprovedExecution(_ context.Context, _, planID string, _ *DeployResult) error {
	h.linked = append(h.linked, planID)
	return nil
}

func approvedEvent(t *testing.T, request *types.ApprovalRequest) *types.OutboxEvent {
	t.Helper()
	raw, err := json.Marshal(types.ApprovalPayload{OrgID: request.OrgID, ApprovalID: request.ID, ItemID: request.ItemID, State: types.ApprovalStateApproved})
	if err != nil {
		t.Fatal(err)
	}
	return &types.OutboxEvent{EventType: types.EventApprovalDecided, Payload: raw}
}

func TestPermanentResumeAdmissionDenialIsTerminalAndAudited(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   string
		action string
	}{
		{name: "deploy signature", code: artifactadmission.CodeSignatureInvalid},
		{name: "deploy provenance", code: artifactadmission.CodeProvenanceInvalid},
		{name: "spec update evidence", code: artifactadmission.CodeTestEvidenceInvalid, action: GateActionInstanceUpdate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := &types.CatalogItem{ID: "core/web-service", SourceID: "core", Name: "web-service"}
			catalog := &denialCatalog{
				item: item, version: &types.CatalogItemVersion{ItemID: item.ID, Version: "1.0.0"},
				admitErr: &artifactadmission.Error{Code: tc.code, Err: errors.New("verified evidence is invalid")},
			}
			service, database := newAdmissionWorkflowFixture(t, catalog, &recordingGate{})
			service.audit = audit.NewStore()
			request := &types.ApprovalRequest{
				ID: "approval-denied", OrgID: "org:1", ItemID: item.ID, Version: "1.0.0", ClusterID: "c1",
				Spec: json.RawMessage(`{"name":"orders"}`), Requester: "user:test", Action: tc.action,
			}
			if tc.action == GateActionInstanceUpdate {
				request.InstanceID = "instance-1"
			}
			handler := NewResumeHandler(service, staticApprovalLoader{request: request}, nil)
			if err := handler.Handle(context.Background(), approvedEvent(t, request)); err != nil {
				t.Fatalf("permanent denial must be terminal, got retryable error %v", err)
			}
			if catalog.admitCalls != 1 {
				t.Fatalf("admission calls = %d, want exactly one", catalog.admitCalls)
			}
			var actor, impersonator, objectID, payload string
			if err := database.Pool.QueryRow(context.Background(), `SELECT actor, COALESCE(impersonator, ''), object_id, payload::text
				FROM audit_events WHERE action = 'deploy.admission_denied'`).Scan(&actor, &impersonator, &objectID, &payload); err != nil {
				t.Fatalf("missing terminal denial audit: %v", err)
			}
			if actor != "system:approvals" || impersonator != "user:tenant-1-automation" || objectID != request.ID {
				t.Fatalf("audit identity = %q/%q object %q", actor, impersonator, objectID)
			}
			var decoded map[string]string
			if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded["code"] != tc.code || decoded["itemId"] != item.ID || decoded["version"] != request.Version {
				t.Fatalf("audit payload = %s", payload)
			}
			var outbox, instances int
			var state string
			if err := database.Pool.QueryRow(context.Background(), `SELECT
				(SELECT count(*) FROM outbox),
				(SELECT count(*) FROM resource_instances),
				(SELECT state::text FROM resource_instances WHERE id = 'instance-1')`).Scan(&outbox, &instances, &state); err != nil {
				t.Fatal(err)
			}
			if outbox != 0 || instances != 1 || state != string(types.InstanceStateRunning) {
				t.Fatalf("denial caused later side effects: outbox=%d instances=%d state=%s", outbox, instances, state)
			}
		})
	}
}

func TestResumeRejectsApplicationDigestDrift(t *testing.T) {
	const admittedDigest = "sha256:52ccaee6d4dd272e54bfccda77738b42e1edf0e4a20c27e23f0b6c15d01aef79"
	const reviewedDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	item := &types.CatalogItem{ID: "core/web-service", SourceID: "core", Name: "web-service"}
	catalog := &denialCatalog{item: item, version: &types.CatalogItemVersion{ItemID: item.ID, Version: "1.0.0", ArtifactDigest: admittedDigest}}
	service, database := newAdmissionWorkflowFixture(t, catalog, &recordingGate{})
	planHandler := &recordingDeploymentPlanApprovalHandler{}
	service.WithDeploymentPlanApprovalHandler(planHandler)
	request := &types.ApprovalRequest{ID: "approval-digest-drift", OrgID: "org:1", ItemID: item.ID, Version: "1.0.0", ClusterID: "c1", ArtifactDigest: reviewedDigest, DeploymentPlanID: "dp-1"}
	handler := NewResumeHandler(service, staticApprovalLoader{request: request}, nil)
	if err := handler.Handle(context.Background(), approvedEvent(t, request)); !errors.Is(err, ErrArtifactDigestMismatch) {
		t.Fatalf("resume error = %v, want ErrArtifactDigestMismatch", err)
	}
	if catalog.admitCalls != 1 {
		t.Fatalf("admission calls = %d, want 1", catalog.admitCalls)
	}
	if len(planHandler.revalidated) != 1 || planHandler.revalidated[0] != "dp-1" || len(planHandler.linked) != 0 {
		t.Fatalf("plan resume calls = revalidate %v link %v", planHandler.revalidated, planHandler.linked)
	}
	var outbox int
	if err := database.Pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if outbox != 0 {
		t.Fatalf("digest drift caused %d outbox side effects", outbox)
	}
}

func TestResumePlanRevalidationDenialPrecedesAdmission(t *testing.T) {
	item := &types.CatalogItem{ID: "core/web-service", SourceID: "core", Name: "web-service"}
	catalog := &denialCatalog{item: item, version: &types.CatalogItemVersion{ItemID: item.ID, Version: "1.0.0", ArtifactDigest: "sha256:52ccaee6d4dd272e54bfccda77738b42e1edf0e4a20c27e23f0b6c15d01aef79"}}
	service, _ := newAdmissionWorkflowFixture(t, catalog, &recordingGate{})
	planHandler := &recordingDeploymentPlanApprovalHandler{err: errors.New("plan_stale")}
	service.WithDeploymentPlanApprovalHandler(planHandler)
	request := &types.ApprovalRequest{ID: "approval-plan-stale", OrgID: "org:1", ItemID: item.ID, Version: "1.0.0", ClusterID: "c1", DeploymentPlanID: "dp-stale"}
	handler := NewResumeHandler(service, staticApprovalLoader{request: request}, nil)
	if err := handler.Handle(context.Background(), approvedEvent(t, request)); err != nil {
		t.Fatalf("permanent plan revalidation denial must be terminal: %v", err)
	}
	if len(planHandler.revalidated) != 1 || catalog.admitCalls != 0 || len(planHandler.linked) != 0 {
		t.Fatalf("denial reached apply: revalidate %v admissions %d links %v", planHandler.revalidated, catalog.admitCalls, planHandler.linked)
	}
}

func TestTemporaryResumeAdmissionFailureRemainsRetryable(t *testing.T) {
	item := &types.CatalogItem{ID: "core/web-service", SourceID: "core", Name: "web-service"}
	catalog := &denialCatalog{
		item: item, version: &types.CatalogItemVersion{ItemID: item.ID, Version: "1.0.0"},
		admitErr: &artifactadmission.Error{Code: artifactadmission.CodeUnavailable, Err: errors.New("registry unavailable"), Temporary: true},
	}
	service, database := newAdmissionWorkflowFixture(t, catalog, &recordingGate{})
	service.audit = audit.NewStore()
	request := &types.ApprovalRequest{ID: "approval-outage", OrgID: "org:1", ItemID: item.ID, Version: "1.0.0", ClusterID: "c1"}
	handler := NewResumeHandler(service, staticApprovalLoader{request: request}, nil)
	if err := handler.Handle(context.Background(), approvedEvent(t, request)); err == nil {
		t.Fatal("temporary admission outage must remain retryable")
	}
	var audits int
	if err := database.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'deploy.admission_denied'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 0 {
		t.Fatalf("temporary outage wrote %d terminal audits", audits)
	}
}
