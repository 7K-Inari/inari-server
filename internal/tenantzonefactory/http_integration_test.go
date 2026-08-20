//go:build integration

package tenantzonefactory

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type itValidator struct{}

func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	if raw == "good" {
		return &authn.Identity{Subject: "pe-1", Organizations: []string{"platform"}}, nil
	}
	return nil, errors.New("invalid token")
}

type itAuthorizer struct{ allow bool }

func (a itAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return a.allow, nil
}
func (a itAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type itTenants map[string]*types.Organization

func (t itTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if o, ok := t[slug]; ok {
		return o, nil
	}
	return nil, tenancy.ErrOrgNotFound
}

type itRoles struct{}

func (itRoles) RoleOf(context.Context, string, string) (types.Role, error) {
	return types.RolePlatformEngineer, nil
}

type itItems struct{}

func (itItems) GetItemByID(context.Context, string) (*types.CatalogItem, error) {
	return nil, errors.New("no items in tzf tests")
}

type itWiring struct {
	wired, unwired int
}

func (w *itWiring) WireZone(_ context.Context, z *types.TenantZone, roleARN string) (*WiringResult, error) {
	w.wired++
	if roleARN == "" {
		return nil, errors.New("role ARN must come from trust bootstrap")
	}
	return &WiringResult{
		OrgID: "org:" + z.Slug, KeycloakOrgID: "kc-" + z.Slug,
		ClusterID: "cluster:" + z.Slug, CloudAccountID: "ca:" + z.Slug,
		GitRepo: z.Slug + "-inari-state",
	}, nil
}
func (w *itWiring) UnwireZone(context.Context, *types.TenantZone) error { w.unwired++; return nil }

type itClusters struct{ cordoned, decommissioned int }

func (c *itClusters) Cordon(context.Context, string, string) error { c.cordoned++; return nil }
func (c *itClusters) Decommission(context.Context, string, string, bool) ([]string, error) {
	c.decommissioned++
	return []string{"i1"}, nil
}

type itFixture struct {
	srv       *httptest.Server
	svc       *Service
	approvals *approvals.Service
	resume    *ResumeHandler
	db        *db.DB
	aws       *FakeOrganizations
	wiring    *itWiring
	clusters  *itClusters
}

func newITFixture(t *testing.T, approvalRequired bool) *itFixture {
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
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:platform','platform','Platform','kc-p');
		 INSERT INTO cloud_accounts (id, org_id, provider, account_id, role_arn, state)
		 VALUES ('ca:mgmt','org:platform','aws','999999999999','arn:aws:iam::999999999999:role/inari-management','active')`); err != nil {
		t.Fatal(err)
	}
	auditStore := audit.NewStore()
	approvalsSvc := approvals.NewService(database, approvals.NewStore(database), auditStore, itRoles{}, itItems{})
	aws := NewFakeOrganizations()
	wiring := &itWiring{}
	clusters := &itClusters{}
	env := &Env{
		AWS: aws, Bootstrap: NewFakeTrustBootstrap(), Prov: NewFakeProvisioner(),
		Wiring: wiring, Clusters: clusters,
		Config: Config{
			ApprovalRequired: approvalRequired, AccountQuota: 10,
			AllowedRegions: []string{"eu-west-1"}, AllowedTiers: []string{"starter"},
			RequiredTags: []string{"cost-center"}, MaxAttempts: 5,
		},
	}
	svc := NewService(database, NewStore(), auditStore, env, approvalsSvc, slog.Default())
	resume := NewResumeHandler(svc, approvalsSvc, slog.Default())
	h := NewHandler(svc, itTenants{"platform": {ID: "org:platform", Slug: "platform"}}, itAuthorizer{allow: true})
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	h.RegisterRoutes(api)
	return &itFixture{
		srv: httptest.NewServer(router), svc: svc, approvals: approvalsSvc,
		resume: resume, db: database, aws: aws, wiring: wiring, clusters: clusters,
	}
}

func (f *itFixture) req(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// decideAndResume mimics the outbox dispatcher: decide the approval, then
// invoke the TZF resume handler with the approval.decided event.
func (f *itFixture) decideAndResume(t *testing.T, approvalID string, approve bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.approvals.Decide(ctx, "org:platform", approvalID, "pe-2", approve, ""); err != nil {
		t.Fatal(err)
	}
	state := types.ApprovalStateRejected
	if approve {
		state = types.ApprovalStateApproved
	}
	payload, _ := json.Marshal(types.ApprovalPayload{OrgID: "org:platform", ApprovalID: approvalID, State: state})
	if err := f.resume.Handle(ctx, &types.OutboxEvent{EventType: types.EventApprovalDecided, Payload: payload}); err != nil {
		t.Fatal(err)
	}
}

func (f *itFixture) drive(t *testing.T, zoneID string, want types.TenantZoneState) *types.TenantZone {
	t.Helper()
	for i := 0; i < 15; i++ {
		if err := f.svc.ResumeZone(context.Background(), zoneID, "test"); err != nil {
			t.Fatalf("resume %d: %v", i, err)
		}
		z, _, err := f.svc.GetZone(context.Background(), zoneID)
		if err != nil {
			t.Fatal(err)
		}
		if z.State == want {
			return z
		}
	}
	z, _, _ := f.svc.GetZone(context.Background(), zoneID)
	t.Fatalf("zone state = %s, want %s", z.State, want)
	return nil
}

func (f *itFixture) auditActions(t *testing.T, zoneID string) []string {
	t.Helper()
	rows, err := f.db.Pool.Query(context.Background(),
		`SELECT action FROM audit_events WHERE object_id = $1 ORDER BY created_at`, zoneID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

// TestZoneVendAndDecommissionEndToEnd is the M3 exit test: a tenant zone is
// vended end-to-end against the fake AWS/Crossplane backends and then
// safely decommissioned, with every step audited (plan §5.12, §10).
func TestZoneVendAndDecommissionEndToEnd(t *testing.T) {
	f := newITFixture(t, true)
	defer f.srv.Close()

	code, body := f.req(t, "POST", "/api/v1/tenants/platform/zones", `{
		"slug":"acme-dev","displayName":"Acme Dev","ouId":"ou-1","region":"eu-west-1",
		"tier":"starter","tags":{"cost-center":"cc-1"},"managementAccountId":"ca:mgmt"}`)
	if code != http.StatusOK {
		t.Fatalf("request zone: %d %s", code, body)
	}
	var out struct {
		Zone       types.TenantZone `json:"zone"`
		ApprovalID string           `json:"approvalId"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.ApprovalID == "" || out.Zone.State != types.ZoneStatePendingApproval {
		t.Fatalf("zone should be pending approval: %+v", out)
	}

	f.decideAndResume(t, out.ApprovalID, true)
	zone := f.drive(t, out.Zone.ID, types.ZoneStateActive)
	if zone.AWSAccountID == "" || zone.OrgID != "org:acme-dev" || zone.ClusterID == "" || zone.GitRepo != "acme-dev-inari-state" {
		t.Errorf("wired zone incomplete: %+v", zone)
	}
	if f.wiring.wired != 1 {
		t.Errorf("wiring ran %d times, want 1 (idempotent)", f.wiring.wired)
	}
	if len(f.aws.CreatedAccounts()) != 1 {
		t.Errorf("vended accounts = %v, want exactly 1", f.aws.CreatedAccounts())
	}

	// Steps are recorded as sub-resources with status.
	_, steps, err := f.svc.GetZone(context.Background(), zone.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range ProvisionOrder {
		if steps[name] == nil || steps[name].Status != types.ZoneStepSucceeded {
			t.Errorf("step %s = %+v, want succeeded", name, steps[name])
		}
	}

	// Decommission: approval-gated, then the flow reverses to closed.
	code, body = f.req(t, "POST", "/api/v1/tenants/platform/zones/"+zone.ID+"/decommission", "")
	if code != http.StatusOK {
		t.Fatalf("decommission request: %d %s", code, body)
	}
	var dout struct {
		ApprovalID string `json:"approvalId"`
	}
	if err := json.Unmarshal([]byte(body), &dout); err != nil {
		t.Fatal(err)
	}
	f.decideAndResume(t, dout.ApprovalID, true)
	zone = f.drive(t, zone.ID, types.ZoneStateClosed)
	if f.clusters.cordoned != 1 || f.clusters.decommissioned != 1 {
		t.Errorf("cluster lifecycle driven %d/%d times, want 1/1", f.clusters.cordoned, f.clusters.decommissioned)
	}
	if f.wiring.unwired != 1 {
		t.Error("identities not revoked exactly once")
	}

	actions := f.auditActions(t, zone.ID)
	joined := strings.Join(actions, ",")
	for _, want := range []string{"tenant_zone.requested", "tenant_zone.step_updated", "tenant_zone.active", "tenant_zone.closed"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit trail %v missing %q", actions, want)
		}
	}
}

// TestZoneManualInterventionAndResume covers the §10 path: an AWS failure
// exhausts the step attempts, the zone parks in manual_intervention, and a
// fixed backend + resume completes the vend.
func TestZoneManualInterventionAndResume(t *testing.T) {
	f := newITFixture(t, false) // approvals off: request starts immediately
	defer f.srv.Close()
	f.aws.FailCreate = true

	code, body := f.req(t, "POST", "/api/v1/tenants/platform/zones", `{
		"slug":"acme-mi","displayName":"Acme MI","ouId":"ou-1","region":"eu-west-1",
		"tier":"starter","tags":{"cost-center":"cc-1"},"managementAccountId":"ca:mgmt"}`)
	if code != http.StatusOK {
		t.Fatalf("request zone: %d %s", code, body)
	}
	var out struct {
		Zone types.TenantZone `json:"zone"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	zone := f.drive(t, out.Zone.ID, types.ZoneStateManualIntervention)
	if zone.Error == "" {
		t.Error("manual_intervention zone should carry the failure reason")
	}

	// Operator fixes the backend and resumes via the API.
	f.aws.FailCreate = false
	code, body = f.req(t, "POST", "/api/v1/tenants/platform/zones/"+zone.ID+"/resume", "")
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("resume: %d %s", code, body)
	}
	f.drive(t, zone.ID, types.ZoneStateActive)
}

// TestZoneAuthzDenied verifies the platform-engineer-only guard.
func TestZoneAuthzDenied(t *testing.T) {
	f := newITFixture(t, true)
	deny := NewHandler(f.svc, itTenants{"platform": {ID: "org:platform", Slug: "platform"}}, itAuthorizer{allow: false})
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, f.db)
	deny.RegisterRoutes(api)
	srv := httptest.NewServer(router)
	defer srv.Close()
	f.srv = srv
	if code, _ := f.req(t, "GET", "/api/v1/tenants/platform/zones", ""); code != http.StatusForbidden {
		t.Errorf("authz denied: got %d, want 403", code)
	}
}
