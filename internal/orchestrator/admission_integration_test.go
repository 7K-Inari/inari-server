//go:build integration

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

type recordingGate struct {
	calls          int
	approved       bool
	artifactDigest string
}

func (g *recordingGate) Gate(_ context.Context, in approvals.GateInput) (*approvals.GateResult, error) {
	g.calls++
	g.artifactDigest = in.ArtifactDigest
	return &approvals.GateResult{Approved: g.approved, ApprovalID: "approval-1"}, nil
}

type admissionTargetResolver struct{}

func (admissionTargetResolver) ResolveResource(ctx context.Context, orgID, _, _ string, _ resourcetargets.Action,
	ref resourcetargets.TargetResourceRef, _ json.RawMessage) (*resourcetargets.ResolvedTarget, error) {
	cluster, err := (admissionCluster{org: orgID}).GetCluster(ctx, ref.ID)
	if err != nil {
		return nil, err
	}
	return &resourcetargets.ResolvedTarget{Cluster: cluster}, nil
}

type admissionPermissions struct{}

func (admissionPermissions) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (admissionPermissions) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func newAdmissionWorkflowFixture(t *testing.T, catalog *denialCatalog, gate *recordingGate) (*Service, *db.DB) {
	t.Helper()
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `
		INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1', 'acme', 'Acme', 'kc-1');
		INSERT INTO clusters (id, org_id, name, state) VALUES ('c1', 'org:1', 'kind-dev', 'active');
	`); err != nil {
		t.Fatal(err)
	}
	instances := inventory.NewStore()
	if err := instances.Create(ctx, database.Pool, &types.ResourceInstance{
		ID: "instance-1", OrgID: "org:1", ClusterID: "c1", CatalogItemID: "core/web-service", Version: "1.0.0",
		Spec: json.RawMessage(`{"name":"payments"}`), State: types.InstanceStateRunning, ManagementMode: types.ManagementModeAdopt,
	}); err != nil {
		t.Fatal(err)
	}
	service := NewService(database, instances, catalog, admissionCluster{org: "org:1"}, gate, nil, nil, nil).
		WithResourceTargets(admissionTargetResolver{}).WithOrgPermissions(admissionPermissions{})
	return service, database
}

func TestAdmissionDenialPrecedesEveryApprovalGate(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*Service) error
	}{
		{name: "deploy", run: func(s *Service) error {
			_, err := s.Deploy(context.Background(), DeployRequest{OrgID: "org:1", ClusterID: "c1", ItemID: "core/web-service", Version: "1.0.0"})
			return err
		}},
		{name: "upgrade", run: func(s *Service) error {
			_, err := s.Upgrade(context.Background(), "org:1", "instance-1", "2.0.0", "", "user:test")
			return err
		}},
		{name: "rollback", run: func(s *Service) error {
			_, err := s.Rollback(context.Background(), "org:1", "instance-1", "0.9.0", "", "user:test")
			return err
		}},
		{name: "spec update", run: func(s *Service) error {
			_, err := s.UpdateSpec(context.Background(), "org:1", "instance-1", json.RawMessage(`{"name":"orders"}`), "", "user:test")
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := &types.CatalogItem{ID: "core/web-service", SourceID: "core", Name: "web-service"}
			catalog := &denialCatalog{
				item: item, version: &types.CatalogItemVersion{ItemID: item.ID, Version: "1.0.0"},
				admitErr: &artifactadmission.Error{Code: artifactadmission.CodeSignatureInvalid, Err: errors.New("bad signature")},
			}
			gate := &recordingGate{}
			service, database := newAdmissionWorkflowFixture(t, catalog, gate)
			err := tc.run(service)
			if !artifactadmission.IsCode(err, artifactadmission.CodeSignatureInvalid) {
				t.Fatalf("error = %v, want signature_invalid", err)
			}
			if gate.calls != 0 || catalog.admitCalls != 1 {
				t.Fatalf("gate calls = %d, admission calls = %d; want zero gate calls after exactly one denial", gate.calls, catalog.admitCalls)
			}
			var approvals int
			if err := database.Pool.QueryRow(context.Background(), `SELECT count(*) FROM approval_requests`).Scan(&approvals); err != nil {
				t.Fatal(err)
			}
			if approvals != 0 {
				t.Fatalf("denied artifact created %d approval requests", approvals)
			}
		})
	}
}

func TestDeployAdmitsBeforePendingAndReusesImmediateAdmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		approved bool
	}{
		{name: "pending approval"},
		{name: "immediate auto approval", approved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := &types.CatalogItem{ID: "core/web-service", SourceID: "core", Name: "web-service"}
			catalog := &denialCatalog{item: item, version: &types.CatalogItemVersion{ItemID: item.ID, Version: "1.0.0", ArtifactDigest: "sha256:52ccaee6d4dd272e54bfccda77738b42e1edf0e4a20c27e23f0b6c15d01aef79"}}
			gate := &recordingGate{approved: tc.approved}
			service, _ := newAdmissionWorkflowFixture(t, catalog, gate)
			result, err := service.Deploy(context.Background(), DeployRequest{OrgID: "org:1", ClusterID: "c1", ItemID: item.ID, Version: "1.0.0"})
			if tc.approved {
				if !errors.Is(err, ErrNoGitConfig) {
					t.Fatalf("error = %v, want ErrNoGitConfig after the auto-approved write begins", err)
				}
			} else {
				if err != nil || result == nil || result.Status != "pending_approval" || result.ApprovalID != "approval-1" {
					t.Fatalf("result = %+v, error = %v; want pending approval", result, err)
				}
				raw, marshalErr := json.Marshal(result)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				var body map[string]any
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Fatal(err)
				}
				if body["artifactDigest"] != "sha256:52ccaee6d4dd272e54bfccda77738b42e1edf0e4a20c27e23f0b6c15d01aef79" {
					t.Fatalf("pending deploy JSON = %s, want admitted artifactDigest", raw)
				}
				if gate.artifactDigest != body["artifactDigest"] {
					t.Fatalf("approval artifact digest = %q, want %q", gate.artifactDigest, body["artifactDigest"])
				}
			}
			if gate.calls != 1 || catalog.admitCalls != 1 {
				t.Fatalf("gate calls = %d, admission calls = %d; want one of each", gate.calls, catalog.admitCalls)
			}
		})
	}
}
