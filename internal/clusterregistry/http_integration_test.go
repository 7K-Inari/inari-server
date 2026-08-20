//go:build integration

package clusterregistry

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
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type itValidator struct{}

// itValidator maps test tokens to identities: "good" belongs to acme+acme2,
// "outsider" to an unrelated org; anything else is rejected.
func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "good":
		return &authn.Identity{Subject: "user-1", Organizations: []string{"acme", "acme2"}}, nil
	case "outsider":
		return &authn.Identity{Subject: "user-2", Organizations: []string{"other"}}, nil
	}
	return nil, errInvalidTestToken
}

var errInvalidTestToken = errors.New("invalid token")

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

type itClients struct{}

func (itClients) CreateClusterClient(context.Context, string) (string, error) {
	return "cluster-x", nil
}
func (itClients) DisableClient(context.Context, string) error { return nil }

func itServer(t *testing.T, az itAuthorizer) (*httptest.Server, *Service) {
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
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES
		 ('org:1','acme','Acme','kc-1'), ('org:2','acme2','Acme2','kc-2')`); err != nil {
		t.Fatal(err)
	}
	svc := NewService(database, itClients{}, NewStore(), audit.NewStore(), time.Hour, false)
	h := NewHandler(svc, itTenants{
		"acme":  {ID: "org:1", Slug: "acme"},
		"acme2": {ID: "org:2", Slug: "acme2"},
	}, az, ManifestParams{AgentImageRepo: "ghcr.io/7k-inari/inari-agent", AgentImageTag: "v0.1.0", GatewayAddress: "https://gw.example.com"}, nil)
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	h.RegisterRoutes(api)
	return httptest.NewServer(router), svc
}

func itReq(t *testing.T, srv *httptest.Server, method, path, token, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func itCreate(t *testing.T, srv *httptest.Server, org, name string) string {
	t.Helper()
	code, body := itReq(t, srv, "POST", "/api/v1/tenants/"+org+"/clusters", "good", `{"name":`+quote(name)+`}`)
	if code != 200 {
		t.Fatalf("create cluster: %d %s", code, body)
	}
	var out struct {
		Cluster types.Cluster `json:"cluster"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out.Cluster.ID
}

func quote(s string) string { return `"` + s + `"` }

// TestClusterAPIAuthAndTenancy covers the REST security surface: bearer
// enforcement, org membership, OpenFGA denial, cross-tenant object access.
func TestClusterAPIAuthAndTenancy(t *testing.T) {
	srv, _ := itServer(t, itAuthorizer{allow: true})
	defer srv.Close()

	if code, _ := itReq(t, srv, "GET", "/api/v1/tenants/acme/clusters", "", ""); code != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", code)
	}
	if code, _ := itReq(t, srv, "GET", "/api/v1/tenants/acme/clusters", "junk", ""); code != http.StatusUnauthorized {
		t.Errorf("bad token: got %d, want 401", code)
	}
	if code, _ := itReq(t, srv, "GET", "/api/v1/tenants/acme/clusters", "outsider", ""); code != http.StatusForbidden {
		t.Errorf("non-member: got %d, want 403", code)
	}

	cid := itCreate(t, srv, "acme", "kind-dev")

	// Cross-tenant: caller is a member of acme2, but the cluster lives in
	// acme — object access by ID must not leak across tenants.
	for _, suffix := range []string{"", "/tokens", "/approve", "/revoke", "/install-manifest"} {
		method := "GET"
		if suffix != "" {
			method = "POST"
		}
		if code, _ := itReq(t, srv, method, "/api/v1/tenants/acme2/clusters/"+cid+suffix, "good", ""); code != http.StatusNotFound {
			t.Errorf("cross-tenant %s %s: got %d, want 404", method, suffix, code)
		}
	}

	// Duplicate name conflicts; empty name fails validation.
	if code, _ := itReq(t, srv, "POST", "/api/v1/tenants/acme/clusters", "good", `{"name":"kind-dev"}`); code != http.StatusConflict {
		t.Errorf("duplicate name: got %d, want 409", code)
	}
	if code, _ := itReq(t, srv, "POST", "/api/v1/tenants/acme/clusters", "good", `{"name":""}`); code == http.StatusOK {
		t.Error("empty name accepted")
	}
}

// TestClusterAPITokenAndManifest verifies token issuance and manifest
// rendering over REST, and that the manifest embeds a usable one-time token.
func TestClusterAPITokenAndManifest(t *testing.T) {
	srv, _ := itServer(t, itAuthorizer{allow: true})
	defer srv.Close()
	cid := itCreate(t, srv, "acme", "c1")

	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/clusters/"+cid+"/tokens", "good", "")
	if code != http.StatusOK {
		t.Fatalf("issue token: %d %s", code, body)
	}
	var tokOut struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &tokOut); err != nil {
		t.Fatal(err)
	}
	if tokOut.Token == "" {
		t.Fatal("empty plaintext token")
	}

	code, body = itReq(t, srv, "POST", "/api/v1/tenants/acme/clusters/"+cid+"/install-manifest", "good", "")
	if code != http.StatusOK {
		t.Fatalf("manifest: %d %s", code, body)
	}
	if !strings.Contains(body, "registration-token:") {
		t.Error("manifest missing bootstrap token")
	}
	if !strings.Contains(body, `"ghcr.io/7k-inari/inari-agent:v0.1.0"`) {
		t.Error("manifest missing published agent image reference")
	}
	if strings.Contains(body, "kubeconfig") {
		t.Error("manifest must never contain a kubeconfig")
	}
}

// TestClusterAPIRevokeFlow verifies revocation blocks further token issuance
// and approval of non-pending clusters conflicts.
func TestClusterAPIRevokeFlow(t *testing.T) {
	srv, _ := itServer(t, itAuthorizer{allow: true})
	defer srv.Close()
	cid := itCreate(t, srv, "acme", "c1")

	if code, _ := itReq(t, srv, "POST", "/api/v1/tenants/acme/clusters/"+cid+"/revoke", "good", ""); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := itReq(t, srv, "POST", "/api/v1/tenants/acme/clusters/"+cid+"/tokens", "good", ""); code != http.StatusConflict {
		t.Errorf("token on revoked: got %d, want 409", code)
	}
	if code, _ := itReq(t, srv, "POST", "/api/v1/tenants/acme/clusters/"+cid+"/approve", "good", ""); code != http.StatusConflict {
		t.Errorf("approve non-pending: got %d, want 409", code)
	}
}

// TestClusterAPIAuthzDenied verifies OpenFGA denial maps to 403.
func TestClusterAPIAuthzDenied(t *testing.T) {
	srv, _ := itServer(t, itAuthorizer{allow: false})
	defer srv.Close()
	if code, _ := itReq(t, srv, "GET", "/api/v1/tenants/acme/clusters", "good", ""); code != http.StatusForbidden {
		t.Errorf("authz denied: got %d, want 403", code)
	}
}

// TestClusterLifecycleFlow covers cordon/uncordon and the decommission
// ownership check (plan §5.11, §10).
func TestClusterLifecycleFlow(t *testing.T) {
	srv, svc := itServer(t, itAuthorizer{allow: true})
	defer srv.Close()
	ctx := context.Background()
	cid := itCreate(t, srv, "acme", "lc1")
	if err := svc.MarkRegistered(ctx, "user-1", cid, "cluster-x", "v1.30.0", nil); err != nil {
		t.Fatal(err)
	}

	base := "/api/v1/tenants/acme/clusters/" + cid
	if code, body := itReq(t, srv, "POST", base+"/cordon", "good", ""); code != http.StatusOK {
		t.Fatalf("cordon: %d %s", code, body)
	}
	c, err := svc.GetCluster(ctx, cid)
	if err != nil || c.State != types.ClusterStateCordoned {
		t.Fatalf("state = %v, %v; want cordoned", c.State, err)
	}
	if code, body := itReq(t, srv, "POST", base+"/uncordon", "good", ""); code != http.StatusOK {
		t.Fatalf("uncordon: %d %s", code, body)
	}
	if code, _ := itReq(t, srv, "POST", base+"/uncordon", "good", ""); code != http.StatusConflict {
		t.Errorf("uncordon from active: got %d, want 409", code)
	}
	if code, body := itReq(t, srv, "POST", base+"/decommission", "good", `{}`); code != http.StatusOK {
		t.Fatalf("decommission: %d %s", code, body)
	}
	c, err = svc.GetCluster(ctx, cid)
	if err != nil || c.State != types.ClusterStateDecommissioned {
		t.Fatalf("state = %v, %v; want decommissioned", c.State, err)
	}
	if code, _ := itReq(t, srv, "POST", base+"/cordon", "good", ""); code != http.StatusConflict {
		t.Errorf("cordon after decommission: got %d, want 409", code)
	}
}

// TestClusterDecommissionOwnershipBlock verifies that non-Inari-managed
// instances block the drain without force (§10).
func TestClusterDecommissionOwnershipBlock(t *testing.T) {
	srv, svc := itServer(t, itAuthorizer{allow: true})
	defer srv.Close()
	ctx := context.Background()
	cid := itCreate(t, srv, "acme", "lc2")
	if err := svc.MarkRegistered(ctx, "user-1", cid, "cluster-x", "v1.30.0", nil); err != nil {
		t.Fatal(err)
	}
	// Seed instances directly: one adopted, one observe-only.
	svc.WithInstanceLister(InstanceListerFunc(func(context.Context, string, string) ([]types.ResourceInstance, error) {
		return []types.ResourceInstance{
			{ID: "i1", ManagementMode: types.ManagementModeAdopt},
			{ID: "i2", ManagementMode: types.ManagementModeObserveOnly},
		}, nil
	}))
	base := "/api/v1/tenants/acme/clusters/" + cid
	if code, body := itReq(t, srv, "POST", base+"/decommission", "good", `{}`); code != http.StatusConflict {
		t.Fatalf("decommission with shared resources: got %d %s, want 409", code, body)
	}
	code, body := itReq(t, srv, "POST", base+"/decommission", "good", `{"force":true}`)
	if code != http.StatusOK {
		t.Fatalf("force decommission: %d %s", code, body)
	}
	var out struct {
		DrainedInstanceIDs []string `json:"drainedInstanceIds"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.DrainedInstanceIDs) != 1 || out.DrainedInstanceIDs[0] != "i1" {
		t.Errorf("drained = %v, want [i1]", out.DrainedInstanceIDs)
	}
	_ = ctx
}
