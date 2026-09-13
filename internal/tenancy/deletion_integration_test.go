//go:build integration

package tenancy_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeGate captures the lifecycle approval request and returns a fixed id.
type fakeGate struct {
	nextID   int
	requests []fakeGateRequest
}

type fakeGateRequest struct {
	orgID, action, requester string
	context                  json.RawMessage
}

func (g *fakeGate) RequestLifecycleApproval(_ context.Context, orgID, action, requester string, c json.RawMessage) (string, error) {
	g.nextID++
	g.requests = append(g.requests, fakeGateRequest{orgID, action, requester, c})
	return fmt.Sprintf("appr-%d", g.nextID), nil
}

// fakeRevoker records force-revoked clusters.
type fakeRevoker struct {
	clusters []types.Cluster
	revoked  []string
}

func (f *fakeRevoker) ListClusters(context.Context, string) ([]types.Cluster, error) {
	return f.clusters, nil
}
func (f *fakeRevoker) RevokeCluster(_ context.Context, _, clusterID string) error {
	f.revoked = append(f.revoked, clusterID)
	return nil
}

// flakyTuples fails DeleteTuples until told otherwise.
type flakyTuples struct {
	recordingStore
	fail bool
}

func (f *flakyTuples) DeleteTuples(ctx context.Context, t []authz.Tuple) error {
	if f.fail {
		return errors.New("fga unavailable")
	}
	return f.recordingStore.DeleteTuples(ctx, t)
}

// fakeApprovalLoader serves a stored approval for the resume handler.
type fakeApprovalLoader struct{ req *types.ApprovalRequest }

func (f fakeApprovalLoader) Get(context.Context, string, string) (*types.ApprovalRequest, error) {
	return f.req, nil
}

func TestTenantDeletionHappyPath(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	store := tenancy.NewStore()
	auditStore := audit.NewStore()
	gate := &fakeGate{}
	rec := &recordingStore{}
	svc := tenancy.NewService(database, idp, store, auditStore).WithDeletionApprovalGate(gate)
	deleter := tenancy.NewDeleter(database, idp, store, auditStore, rec, nil, slog.Default())
	svc.WithDeleter(deleter)

	org, teams, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	if org.Status != types.OrgStatusActive {
		t.Fatalf("new org status = %q, want active", org.Status)
	}

	approvalID, err := svc.DeleteTenant(ctx, "user-1", "acme", false, "e2e cleanup")
	if err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	if approvalID != "appr-1" {
		t.Fatalf("approvalID = %q", approvalID)
	}
	if len(gate.requests) != 1 || gate.requests[0].action != types.ApprovalActionTenantDecommission {
		t.Fatalf("gate requests = %+v", gate.requests)
	}

	// Org is frozen immediately.
	frozen, err := store.GetOrganizationBySlug(ctx, database.Pool, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Status != types.OrgStatusDeleting {
		t.Errorf("status = %q, want deleting", frozen.Status)
	}

	// Idempotent re-request returns the same approval id.
	again, err := svc.DeleteTenant(ctx, "user-1", "acme", false, "")
	if err != nil || again != approvalID {
		t.Errorf("idempotent re-request: id=%q err=%v", again, err)
	}

	// Approval granted: run the teardown.
	if err := deleter.Run(ctx, org.ID); err != nil {
		t.Fatalf("deleter.Run: %v", err)
	}

	// Org row and cascading children are gone.
	if _, err := store.GetOrganizationBySlug(ctx, database.Pool, "acme"); !errors.Is(err, tenancy.ErrOrgNotFound) {
		t.Errorf("org after teardown: err = %v, want ErrOrgNotFound", err)
	}
	countOrgRows := func(table, column string) int {
		var n int
		if err := database.Pool.QueryRow(ctx,
			fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s = $1`, table, column), org.ID).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}
	for table, col := range map[string]string{
		"organizations": "id", "teams": "org_id", "memberships": "org_id", "tenant_deletions": "org_id",
	} {
		if n := countOrgRows(table, col); n != 0 {
			t.Errorf("%s rows for org = %d, want 0", table, n)
		}
	}

	// Audit retained in the archive; live audit only holds tenant.deleted.
	var n int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_archive WHERE org_id = $1`, org.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("audit_archive is empty, want the org's archived audit rows")
	}
	var liveActions []string
	rows, err := database.Pool.Query(ctx, `SELECT action FROM audit_events WHERE org_id = $1`, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		liveActions = append(liveActions, a)
	}
	if len(liveActions) != 1 || liveActions[0] != "tenant.deleted" {
		t.Errorf("live audit actions = %v, want [tenant.deleted]", liveActions)
	}

	// Outbox holds no published rows for the dead org (archive purges them);
	// pending rows may remain and dead-letter out.
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE org_id = $1 AND published_at IS NOT NULL`, org.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("published outbox rows = %d, want 0 (archived)", n)
	}

	// FGA tuples retracted: one org role tuple per default team + the
	// creator's two membership tuples (org-admins + platform-team).
	if len(rec.deleted) != len(teams)+2 {
		t.Errorf("deleted tuples = %d, want %d: %+v", len(rec.deleted), len(teams)+2, rec.deleted)
	}
	for _, tup := range rec.deleted {
		if !strings.Contains(tup.Object, "organization:kc-acme") && !strings.HasPrefix(tup.Object, "team:") {
			t.Errorf("unexpected deleted tuple %+v", tup)
		}
	}

	// Keycloak org is gone.
	idp.mu.Lock()
	_, orgExists := idp.orgs[org.KeycloakOrgID]
	idp.mu.Unlock()
	if orgExists {
		t.Error("keycloak org still exists after teardown")
	}

	// Re-running is a no-op (row cascaded away).
	if err := deleter.Run(ctx, org.ID); err != nil {
		t.Errorf("second Run: %v", err)
	}
}

func TestTenantDeletionBlockersAndForce(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	store := tenancy.NewStore()
	auditStore := audit.NewStore()
	gate := &fakeGate{}
	rec := &recordingStore{}
	revoker := &fakeRevoker{}
	svc := tenancy.NewService(database, idp, store, auditStore).WithDeletionApprovalGate(gate)
	deleter := tenancy.NewDeleter(database, idp, store, auditStore, rec, revoker, slog.Default())
	svc.WithDeleter(deleter)

	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO clusters (id, org_id, name, state) VALUES ('c-1', $1, 'prod', 'active')`, org.ID); err != nil {
		t.Fatal(err)
	}
	revoker.clusters = []types.Cluster{{ID: "c-1", OrgID: org.ID, State: types.ClusterStateActive}}

	// Non-forced deletion is rejected with the dependency list.
	_, err = svc.DeleteTenant(ctx, "user-1", "acme", false, "")
	var depErr *tenancy.DependencyError
	if !errors.As(err, &depErr) {
		t.Fatalf("DeleteTenant err = %v, want DependencyError", err)
	}
	if len(depErr.Blockers) != 1 || depErr.Blockers[0].Kind != "cluster" || depErr.Blockers[0].ID != "c-1" {
		t.Errorf("blockers = %+v", depErr.Blockers)
	}
	// Org stays active after a rejected request.
	stillActive, _ := store.GetOrganizationBySlug(ctx, database.Pool, "acme")
	if stillActive.Status != types.OrgStatusActive {
		t.Errorf("status after rejected delete = %q, want active", stillActive.Status)
	}

	// Dry-run endpoint surface returns the same blockers.
	blockers, err := svc.DeletionDependencies(ctx, "acme")
	if err != nil || len(blockers) != 1 {
		t.Errorf("DeletionDependencies = %+v, %v", blockers, err)
	}

	// Force revokes the cluster as part of teardown.
	if _, err := svc.DeleteTenant(ctx, "user-1", "acme", true, "force"); err != nil {
		t.Fatalf("forced DeleteTenant: %v", err)
	}
	if err := deleter.Run(ctx, org.ID); err != nil {
		t.Fatalf("deleter.Run: %v", err)
	}
	if len(revoker.revoked) != 1 || revoker.revoked[0] != "c-1" {
		t.Errorf("revoked = %v, want [c-1]", revoker.revoked)
	}
	var n int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM clusters WHERE org_id = $1`, org.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("clusters for org = %d, want 0", n)
	}
}

func TestTenantDeletionDeniedRestoresOrg(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	store := tenancy.NewStore()
	auditStore := audit.NewStore()
	gate := &fakeGate{}
	rec := &recordingStore{}
	svc := tenancy.NewService(database, idp, store, auditStore).WithDeletionApprovalGate(gate)
	deleter := tenancy.NewDeleter(database, idp, store, auditStore, rec, nil, slog.Default())
	svc.WithDeleter(deleter)

	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	approvalID, err := svc.DeleteTenant(ctx, "user-1", "acme", false, "")
	if err != nil {
		t.Fatal(err)
	}

	spec, _ := json.Marshal(map[string]string{"orgId": org.ID, "slug": "acme"})
	loader := fakeApprovalLoader{req: &types.ApprovalRequest{
		ID: approvalID, OrgID: org.ID, Action: types.ApprovalActionTenantDecommission, Spec: spec,
	}}
	handler := tenancy.NewDeletionResumeHandler(svc, deleter, loader, slog.Default())
	payload, _ := json.Marshal(types.ApprovalPayload{
		OrgID: org.ID, ApprovalID: approvalID, State: types.ApprovalStateRejected,
	})
	if err := handler.Handle(ctx, &types.OutboxEvent{
		EventType: types.EventApprovalDecided, Payload: payload,
	}); err != nil {
		t.Fatal(err)
	}

	restored, err := store.GetOrganizationBySlug(ctx, database.Pool, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if restored.Status != types.OrgStatusActive {
		t.Errorf("status after denial = %q, want active", restored.Status)
	}
	if _, err := store.GetTenantDeletion(ctx, database.Pool, org.ID); !errors.Is(err, tenancy.ErrDeletionNotFound) {
		t.Errorf("deletion row after denial: err = %v, want ErrDeletionNotFound", err)
	}
	var n int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE org_id = $1 AND action = 'tenant.decommission_denied'`, org.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("denial audit rows = %d, want 1", n)
	}
}

func TestTenantDeletionResumeAfterFailure(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	store := tenancy.NewStore()
	auditStore := audit.NewStore()
	gate := &fakeGate{}
	flaky := &flakyTuples{fail: true}
	svc := tenancy.NewService(database, idp, store, auditStore).WithDeletionApprovalGate(gate)
	deleter := tenancy.NewDeleter(database, idp, store, auditStore, flaky, nil, slog.Default())
	svc.WithDeleter(deleter)

	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DeleteTenant(ctx, "user-1", "acme", false, ""); err != nil {
		t.Fatal(err)
	}

	// FGA cleanup fails: deletion flips to delete_failed and stops.
	if err := deleter.Run(ctx, org.ID); err == nil {
		t.Fatal("Run with failing FGA store: want error")
	}
	del, err := store.GetTenantDeletion(ctx, database.Pool, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if del.State != types.TenantDeletionStateFailed || del.LastError == "" {
		t.Errorf("deletion = %+v, want delete_failed with last_error", del)
	}
	if del.Step != "archive_audit" {
		t.Errorf("resumed step = %q, want archive_audit (fga_cleanup failed)", del.Step)
	}

	// Startup resume scan also surfaces the failure without crashing.
	deleter.ResumePendingDeletions(ctx)

	// Fix FGA and retry via the service: resumes at fga_cleanup, completes.
	flaky.fail = false
	final, err := svc.RetryDeletion(ctx, "acme")
	if err != nil {
		t.Fatalf("RetryDeletion: %v", err)
	}
	if final.State != types.OrgStatusDeleted {
		t.Errorf("final state = %q, want deleted", final.State)
	}
	if _, err := store.GetOrganizationBySlug(ctx, database.Pool, "acme"); !errors.Is(err, tenancy.ErrOrgNotFound) {
		t.Errorf("org after retry: err = %v, want ErrOrgNotFound", err)
	}
	if len(flaky.deleted) == 0 {
		t.Error("FGA tuples were not retracted on retry")
	}
}

func TestAuditEventsStayAppendOnly(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	// Without the GUC the trigger still rejects deletes.
	if _, err := database.Pool.Exec(ctx, `DELETE FROM audit_events WHERE org_id = $1`, org.ID); err == nil {
		t.Fatal("DELETE on audit_events succeeded without the archive GUC, want append-only error")
	}
}

func TestDeleteTenantHTTP(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	store := tenancy.NewStore()
	auditStore := audit.NewStore()
	gate := &fakeGate{}
	rec := &recordingStore{}
	svc := tenancy.NewService(database, idp, store, auditStore).WithDeletionApprovalGate(gate)
	svc.WithDeleter(tenancy.NewDeleter(database, idp, store, auditStore, rec, nil, slog.Default()))
	if _, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}

	newServer := func(id *authn.Identity, gate relationGate) *httptest.Server {
		router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(nil, nil)), fixedValidator{id: id}, readyOK{})
		tenancy.NewHandler(svc, gate).RegisterRoutes(api)
		srv := httptest.NewServer(router)
		t.Cleanup(srv.Close)
		return srv
	}
	do := func(srv *httptest.Server, method, path, body string) (int, string) {
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer good")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw := make([]byte, 0, 4096)
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			raw = append(raw, buf[:n]...)
			if err != nil {
				break
			}
		}
		return resp.StatusCode, string(raw)
	}

	member := &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}
	stranger := &authn.Identity{Subject: "user-9", Organizations: []string{"other"}}
	adminSrv := newServer(member, relationGate{relation: "admin"})
	viewerSrv := newServer(member, relationGate{relation: "viewer"})
	strangerSrv := newServer(stranger, relationGate{relation: "admin"})

	// Coarse PEP: non-member rejected.
	if code, _ := do(strangerSrv, http.MethodDelete, "/api/v1/tenants/acme", `{}`); code != http.StatusForbidden {
		t.Errorf("stranger DELETE: got %d, want 403", code)
	}
	// Fine PEP: viewer cannot delete.
	if code, _ := do(viewerSrv, http.MethodDelete, "/api/v1/tenants/acme", `{}`); code != http.StatusForbidden {
		t.Errorf("viewer DELETE: got %d, want 403", code)
	}
	// Unknown org 404s.
	if code, _ := do(newServer(&authn.Identity{Subject: "user-1", Organizations: []string{"ghost"}}, relationGate{relation: "admin"}),
		http.MethodDelete, "/api/v1/tenants/ghost", `{}`); code != http.StatusNotFound {
		t.Errorf("ghost DELETE: got %d, want 404", code)
	}
	// Happy path: 202 with an approval id.
	code, body := do(adminSrv, http.MethodDelete, "/api/v1/tenants/acme", `{"reason":"cleanup"}`)
	if code != http.StatusAccepted {
		t.Fatalf("admin DELETE: got %d %s, want 202", code, body)
	}
	if !strings.Contains(body, `"approvalId":"appr-1"`) {
		t.Errorf("DELETE body = %s", body)
	}
	// GET reports the deleting status + progress.
	code, body = do(adminSrv, http.MethodGet, "/api/v1/tenants/acme", "")
	if code != http.StatusOK || !strings.Contains(body, `"status":"deleting"`) || !strings.Contains(body, `"deletion"`) {
		t.Errorf("GET deleting tenant: %d %s", code, body)
	}
	// Mutating routes reject writes on a deleting tenant.
	if code, _ := do(adminSrv, http.MethodPatch, "/api/v1/tenants/acme", `{"displayName":"X"}`); code != http.StatusConflict {
		t.Errorf("PATCH deleting tenant: got %d, want 409", code)
	}
	if code, _ := do(adminSrv, http.MethodPost, "/api/v1/tenants/acme/teams", `{"name":"x"}`); code != http.StatusConflict {
		t.Errorf("POST team on deleting tenant: got %d, want 409", code)
	}
	// Retry on a non-failed deletion is an error (500 surfaced; state guard).
	if code, _ := do(adminSrv, http.MethodPost, "/api/v1/tenants/acme/deletion:retry", ""); code == http.StatusAccepted {
		t.Error("retry on non-failed deletion: got 202, want error")
	}
}

func TestTenantDeletionTupleWriterSweep(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	store := tenancy.NewStore()
	auditStore := audit.NewStore()
	gate := &fakeGate{}
	rec := &recordingStore{}
	svc := tenancy.NewService(database, idp, store, auditStore).WithDeletionApprovalGate(gate)
	svc.WithDeleter(tenancy.NewDeleter(database, idp, store, auditStore, rec, nil, slog.Default()))

	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DeleteTenant(ctx, "user-1", "acme", false, ""); err != nil {
		t.Fatal(err)
	}
	// Dispatch pending outbox events: the tenant.deleting sweep must retract
	// tuples through the TupleWriter too (defensive second path).
	disp := audit.NewDispatcher(database, 50*time.Millisecond, authz.NewTupleWriter(rec))
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	foundRole := false
	for _, tup := range rec.deleted {
		if tup.Object == "organization:"+org.KeycloakOrgID {
			foundRole = true
		}
	}
	if !foundRole {
		t.Errorf("tuplewriter sweep did not retract org role tuples: %+v", rec.deleted)
	}
}
