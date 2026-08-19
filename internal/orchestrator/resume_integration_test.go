//go:build integration

package orchestrator_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// itPolicyChecker always returns the configured pre-flight decision.
type itPolicyChecker struct{ decision *types.PolicyDecision }

func (p itPolicyChecker) PreFlight(context.Context, orchestrator.PolicyInput) (*types.PolicyDecision, error) {
	return p.decision, nil
}
func (p itPolicyChecker) RenderCheck(context.Context, string, ...[]byte) (*types.PolicyDecision, error) {
	return &types.PolicyDecision{Allow: true}, nil
}

// itServerM3 is itServer plus the approval-resume dispatcher and an optional
// policy checker. Returns the services the M3 flows need to drive directly.
func itServerM3(t *testing.T, checker orchestrator.PolicyChecker) (*httptest.Server, *db.DB, *gitprovider.Fake, *itQueue, *approvals.Service, *audit.Dispatcher) {
	t.Helper()
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("inari"),
		postgres.WithUsername("inari"),
		postgres.WithPassword("inari"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
	)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	url, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	seed := `
		INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1');
		INSERT INTO users (id, email) VALUES ('user-1','a@x.io'), ('user-2','b@x.io');
		INSERT INTO memberships (user_id, org_id, role) VALUES
		  ('user-1','org:1','developer'), ('user-2','org:1','platform-engineer');
		INSERT INTO clusters (id, org_id, name, state) VALUES ('cluster-1','org:1','kind-dev','active');
		INSERT INTO tenant_git_configs (org_id, repo, commit_policy, base_branch)
		  VALUES ('org:1','inari-dev/acme-inari-state','direct','main');`
	if _, err := database.Pool.Exec(ctx, seed); err != nil {
		t.Fatal(err)
	}

	auditStore := audit.NewStore()
	tenancySvc := tenancy.NewService(database, nil, tenancy.NewStore(), auditStore)
	catalogSvc := catalog.NewService(database, catalog.NewStore(), nil, auditStore,
		&catalog.FixturePuller{Root: "../catalog/testdata/oci"})
	if _, err := catalogSvc.Sync(ctx); err != nil {
		t.Fatalf("catalog sync: %v", err)
	}
	approvalsSvc := approvals.NewService(database, approvals.NewStore(database), auditStore, tenancySvc, catalogSvc)
	inventorySvc := inventory.NewService(database, inventory.NewStore(), auditStore, catalogSvc)
	git := gitprovider.NewFake()
	queue := &itQueue{}
	orchSvc := orchestrator.NewService(database, inventory.NewStore(), catalogSvc, itClusters{},
		approvalsSvc, queue, git, auditStore)
	if checker != nil {
		orchSvc = orchSvc.WithPolicyChecker(checker)
	}
	dispatcher := audit.NewDispatcher(database, time.Millisecond,
		orchestrator.NewResumeHandler(orchSvc, approvalsSvc, slog.Default()))

	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	catalog.NewHandler(catalogSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	approvals.NewHandler(approvalsSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	inventory.NewHandler(inventorySvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	orchestrator.NewHandler(orchSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	return httptest.NewServer(router), database, git, queue, approvalsSvc, dispatcher
}

// TestApprovalGateResume is the M3 acceptance path: the approval gate blocks
// the deploy (pending_approval), approval releases it automatically — the
// instance materializes via the outbox-driven resume, and the audit record
// carries both the system actor and the impersonated virtual user (§5.4).
func TestApprovalGateResume(t *testing.T) {
	srv, database, git, queue, _, dispatcher := itServerM3(t, nil)
	defer srv.Close()
	ctx := context.Background()

	if _, err := database.Pool.Exec(ctx,
		`UPDATE catalog_items SET approval_policy = 'peer' WHERE id = 'curated:web-service'`); err != nil {
		t.Fatal(err)
	}

	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "good",
		`{"itemId":"curated:web-service","clusterId":"cluster-1","name":"web","namespace":"apps","spec":{"hostname":"app.example.com"}}`)
	if code != http.StatusOK {
		t.Fatalf("deploy: %d %s", code, body)
	}
	var out struct {
		Deploy orchestrator.DeployResult `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Deploy.Status != "pending_approval" {
		t.Fatalf("expected pending_approval, got %+v", out.Deploy)
	}
	if len(queue.cmds) != 0 {
		t.Fatalf("no agent command expected before approval, got %d", len(queue.cmds))
	}

	// The gate stored the full deploy context for resume.
	var name, ns string
	if err := database.Pool.QueryRow(ctx,
		`SELECT name, namespace FROM approval_requests WHERE id = $1`, out.Deploy.ApprovalID).Scan(&name, &ns); err != nil {
		t.Fatal(err)
	}
	if name != "web" || ns != "apps" {
		t.Errorf("stored resume context = %q/%q, want web/apps", name, ns)
	}

	// Peer approves → outbox event → resume.
	code, body = itReq(t, srv, "POST", "/api/v1/tenants/acme/approvals/"+out.Deploy.ApprovalID+"/decide", "peer", `{"approve":true}`)
	if code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, body)
	}
	if err := dispatcher.DispatchOnce(ctx); err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	// The deploy materialized without the caller re-issuing it.
	if len(queue.cmds) != 1 {
		t.Fatalf("queued commands after resume = %d, want 1", len(queue.cmds))
	}
	files := git.Files("inari-dev/acme-inari-state", "main")
	if _, ok := files["clusters/cluster-1/web-service/web/instance.yaml"]; !ok {
		t.Fatalf("resumed deploy not committed: %v", keysOf(files))
	}

	// Double audit: real actor = system automation, impersonator = tenant
	// virtual user (§5.4).
	var actor, impersonator string
	err := database.Pool.QueryRow(ctx,
		`SELECT actor, COALESCE(impersonator,'') FROM audit_events
		 WHERE action = 'deploy.requested' AND object_id = 'web'`).Scan(&actor, &impersonator)
	if err != nil {
		t.Fatalf("audit lookup: %v", err)
	}
	if actor != "system:approvals" || impersonator != "user:tenant-1-automation" {
		t.Errorf("double audit = %q/%q, want system:approvals / user:tenant-1-automation", actor, impersonator)
	}
}

// TestApprovalCancelAndExpiry covers requester cancel, non-requester cancel
// rejection, and the expiry sweep.
func TestApprovalCancelAndExpiry(t *testing.T) {
	srv, database, _, _, approvalsSvc, _ := itServerM3(t, nil)
	defer srv.Close()
	ctx := context.Background()
	if _, err := database.Pool.Exec(ctx,
		`UPDATE catalog_items SET approval_policy = 'peer' WHERE id = 'curated:web-service'`); err != nil {
		t.Fatal(err)
	}

	gateDeploy := func(t *testing.T, name string) string {
		t.Helper()
		code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "good",
			`{"itemId":"curated:web-service","clusterId":"cluster-1","name":"`+name+`","spec":{"hostname":"x.example.com"}}`)
		if code != http.StatusOK {
			t.Fatalf("deploy: %d %s", code, body)
		}
		var out struct {
			Deploy orchestrator.DeployResult `json:"deploy"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
		return out.Deploy.ApprovalID
	}

	// Non-requester cannot cancel.
	id1 := gateDeploy(t, "web-cancel")
	if code, _ := itReq(t, srv, "POST", "/api/v1/tenants/acme/approvals/"+id1+"/cancel", "peer", ""); code != http.StatusForbidden {
		t.Errorf("peer cancel: got %d, want 403", code)
	}
	// Requester cancels; a later decision is a conflict.
	if code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/approvals/"+id1+"/cancel", "good", ""); code != http.StatusOK {
		t.Fatalf("requester cancel: %d %s", code, body)
	}
	if code, _ := itReq(t, srv, "POST", "/api/v1/tenants/acme/approvals/"+id1+"/decide", "peer", `{"approve":true}`); code != http.StatusConflict {
		t.Errorf("decide after cancel: got %d, want 409", code)
	}

	// Expiry: a request with a past expiry is swept to expired.
	approvalsSvc.WithTTL(-time.Hour)
	id2 := gateDeploy(t, "web-expire")
	n, err := approvalsSvc.ExpireSweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expired = %d, want 1", n)
	}
	var state string
	if err := database.Pool.QueryRow(ctx, `SELECT state FROM approval_requests WHERE id = $1`, id2).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != types.ApprovalStateExpired {
		t.Errorf("state = %q, want expired", state)
	}
	approvalsSvc.WithTTL(approvals.DefaultTTL)
}

// TestPolicyPreFlightBlocks is the M3 acceptance path: a policy-violating
// deploy is blocked with reason + remediation (422), before any git write.
func TestPolicyPreFlightBlocks(t *testing.T) {
	checker := itPolicyChecker{decision: &types.PolicyDecision{
		Allow: false,
		Violations: []types.PolicyViolation{{
			Rule: "disallowed-registry", Reason: "image not from approved registry",
			Remediation: "use registry.example.com",
		}},
	}}
	srv, _, git, queue, _, _ := itServerM3(t, checker)
	defer srv.Close()

	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "good",
		`{"itemId":"curated:postgres-aws","clusterId":"cluster-1","name":"bad-db","spec":{"storageGB":50}}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("deploy: got %d, want 422 (%s)", code, body)
	}
	if !strings.Contains(body, "image not from approved registry") ||
		!strings.Contains(body, "use registry.example.com") {
		t.Errorf("422 body lacks reason + remediation: %s", body)
	}
	if len(git.Files("inari-dev/acme-inari-state", "main")) != 0 {
		t.Error("blocked deploy reached tenant git")
	}
	if len(queue.cmds) != 0 {
		t.Error("blocked deploy dispatched an agent command")
	}
}
