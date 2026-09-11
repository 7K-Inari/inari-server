//go:build integration

// Approval-gated templates (M8.W6, parent plan §5.3): a manifest with
// scaffold.requiresApproval parks the run in pending_approval after
// rendering; the outbox ResumeHandler resumes it on approval and settles
// it failed on rejection — same pattern as orchestrator deploys.
package scaffold

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// itRoles resolves fixed org roles for the approvals policy checks.
type itRoles map[string]types.Role

func (r itRoles) RoleOf(_ context.Context, _, userID string) (types.Role, error) {
	return r[userID], nil
}

// approvalEnv wires a real approvals.Service (platform-admin policy lives
// on the template's catalog item) plus the scaffold resume handler.
func approvalEnv(t *testing.T, f *itFixture) (*approvals.Service, *ResumeHandler) {
	t.Helper()
	auditStore := audit.NewStore()
	catSvc := catalog.NewService(f.db, catalog.NewStore(), nil, auditStore, nil)
	ap := approvals.NewService(f.db, approvals.NewStore(f.db), auditStore,
		itRoles{"admin-1": types.RoleOrgAdmin, "dev-1": types.RoleDeveloper}, catSvc)
	return ap, NewResumeHandler(f.svc, ap, nil)
}

// decidedEvent builds the approval.decided outbox event the dispatcher
// would deliver.
func decidedEvent(t *testing.T, orgID, approvalID, state string) *types.OutboxEvent {
	t.Helper()
	raw, err := json.Marshal(types.ApprovalPayload{OrgID: orgID, ApprovalID: approvalID, State: state})
	if err != nil {
		t.Fatal(err)
	}
	return &types.OutboxEvent{EventType: types.EventApprovalDecided, Payload: raw}
}

func pendingApprovalID(t *testing.T, f *itFixture, orgID string) string {
	t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(context.Background(),
		`SELECT id FROM approval_requests WHERE org_id = $1 AND state = 'pending'`, orgID).Scan(&id); err != nil {
		t.Fatalf("pending approval request: %v", err)
	}
	return id
}

func TestApprovalGatedRunResumesOnApproval(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", "  requiresApproval: true\n",
		map[string]string{"a.txt.tmpl": "{{ .Values.name }}"})
	ap, resume := approvalEnv(t, f)
	f.svc.WithExecEnv(&ExecEnv{
		Git: gitprovider.NewFake(), GitOrg: "acme-platform", Registrar: &fakeRegistrar{},
		Upsert: &fakeUpserter{}, RBAC: &fakeRBACBinder{},
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(), Gate: ap,
	})
	// The sync maps requiresApproval → the item's platform-admin policy.
	if _, err := f.db.Pool.Exec(ctx,
		`UPDATE catalog_items SET approval_policy = 'platform-admin' WHERE id = 'template:go-service'`); err != nil {
		t.Fatal(err)
	}

	run, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}
	f.svc.reconcileOnce(ctx, time.Minute)

	got, steps, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhasePendingApproval {
		t.Fatalf("phase = %q, want pending_approval", got.Phase)
	}
	if steps[0].Name != "rendering" || steps[0].State != types.ScaffoldStepCompleted {
		t.Fatalf("rendering = %+v", steps[0])
	}
	if steps[1].State != types.ScaffoldStepPending {
		t.Fatalf("creating-repo must not start while gated: %+v", steps[1])
	}
	approvalID := pendingApprovalID(t, f, "org:acme")
	if outputValue(got.Outputs, approvalHoldKey) != approvalID {
		t.Fatalf("outputs = %s, want pendingApprovalId %s", got.Outputs, approvalID)
	}

	// A second reconcile tick must not re-drive or duplicate the request.
	f.svc.reconcileOnce(ctx, time.Minute)
	var reqCount int
	if err := f.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM approval_requests WHERE org_id = 'org:acme'`).Scan(&reqCount); err != nil {
		t.Fatal(err)
	}
	if reqCount != 1 {
		t.Fatalf("approval requests = %d, want exactly 1", reqCount)
	}

	// The developer cannot self-approve under the platform-admin policy.
	if _, err := ap.Decide(ctx, "org:acme", approvalID, "dev-1", true, ""); err == nil {
		t.Fatal("developer self-approval must be rejected")
	}
	// An org admin approves → the resume handler flips the run back and
	// the next tick drives it to completion.
	if _, err := ap.Decide(ctx, "org:acme", approvalID, "admin-1", true, "lgtm"); err != nil {
		t.Fatal(err)
	}
	if err := resume.Handle(ctx, decidedEvent(t, "org:acme", approvalID, types.ApprovalStateApproved)); err != nil {
		t.Fatal(err)
	}
	got, _, err = f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseCreatingRepo {
		t.Fatalf("phase after approval = %q, want creating-repo", got.Phase)
	}
	// The hold marker is kept so the resumed run never re-requests.
	if outputValue(got.Outputs, approvalHoldKey) != approvalID {
		t.Fatalf("approval marker lost: %s", got.Outputs)
	}

	f.svc.reconcileOnce(ctx, time.Minute)
	got, _, err = f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseCompleted {
		t.Fatalf("final phase = %q (error=%q), want completed", got.Phase, got.Error)
	}
}

func TestApprovalGatedRunRejected(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", "  requiresApproval: true\n",
		map[string]string{"a.txt.tmpl": "{{ .Values.name }}"})
	ap, resume := approvalEnv(t, f)
	f.svc.WithExecEnv(&ExecEnv{
		Git: gitprovider.NewFake(), GitOrg: "acme-platform", Registrar: &fakeRegistrar{},
		Upsert: &fakeUpserter{}, RBAC: &fakeRBACBinder{},
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(), Gate: ap,
	})
	if _, err := f.db.Pool.Exec(ctx,
		`UPDATE catalog_items SET approval_policy = 'platform-admin' WHERE id = 'template:go-service'`); err != nil {
		t.Fatal(err)
	}

	run, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}
	f.svc.reconcileOnce(ctx, time.Minute)
	approvalID := pendingApprovalID(t, f, "org:acme")

	if _, err := ap.Decide(ctx, "org:acme", approvalID, "admin-1", false, "no"); err != nil {
		t.Fatal(err)
	}
	if err := resume.Handle(ctx, decidedEvent(t, "org:acme", approvalID, types.ApprovalStateRejected)); err != nil {
		t.Fatal(err)
	}
	got, _, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseFailed {
		t.Fatalf("phase after rejection = %q, want failed", got.Phase)
	}
	if got.Error == "" {
		t.Fatal("rejection must record an error")
	}
}

// TestUngatedTemplateSkipsApproval pins the pass-through: no
// requiresApproval → no approval request, run drives to completion.
func TestUngatedTemplateSkipsApproval(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{"a.txt.tmpl": "{{ .Values.name }}"})
	ap, _ := approvalEnv(t, f)
	f.svc.WithExecEnv(&ExecEnv{
		Git: gitprovider.NewFake(), GitOrg: "acme-platform", Registrar: &fakeRegistrar{},
		Upsert: &fakeUpserter{}, RBAC: &fakeRBACBinder{},
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(), Gate: ap,
	})
	run, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}
	f.svc.reconcileOnce(ctx, time.Minute)
	got, _, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseCompleted {
		t.Fatalf("phase = %q, want completed", got.Phase)
	}
	var reqCount int
	if err := f.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM approval_requests WHERE org_id = 'org:acme'`).Scan(&reqCount); err != nil {
		t.Fatal(err)
	}
	if reqCount != 0 {
		t.Fatalf("approval requests = %d, want 0 for ungated template", reqCount)
	}
}
