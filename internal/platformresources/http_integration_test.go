//go:build integration

package platformresources

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

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

// itValidator maps test tokens to identities: "good" belongs to acme+acme2,
// "outsider" to an unrelated org; anything else is rejected.
type itValidator struct{}

func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "good":
		return &authn.Identity{Subject: "user-1", Organizations: []string{"acme", "acme2"}}, nil
	case "outsider":
		return &authn.Identity{Subject: "user-2", Organizations: []string{"other"}}, nil
	case "ghost":
		// Member of an org slug with no tenancy record.
		return &authn.Identity{Subject: "user-3", Organizations: []string{"ghost"}}, nil
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

type itQueue struct{ cmds []*types.AgentCommand }

func (q *itQueue) Enqueue(_ context.Context, cmd *types.AgentCommand) error {
	q.cmds = append(q.cmds, cmd)
	return nil
}

type itClusters struct{ clusters []types.Cluster }

func (c itClusters) ListClusters(context.Context, string) ([]types.Cluster, error) {
	return c.clusters, nil
}

func itServer(t *testing.T, az itAuthorizer) (*httptest.Server, *Service) {
	t.Helper()
	return itServerWithQueue(t, az, &itQueue{})
}

func itServerWithQueue(t *testing.T, az itAuthorizer, queue *itQueue) (*httptest.Server, *Service) {
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
	svc := NewService(database, NewStore(), audit.NewStore()).
		WithCommandQueue(queue).
		WithClusterLister(itClusters{clusters: []types.Cluster{{ID: "cluster:p1"}}}).
		WithTenantResolver(itTenants{"platform": {ID: "org:platform", Slug: "platform"}})
	h := NewHandler(svc, itTenants{
		"acme":  {ID: "org:1", Slug: "acme"},
		"acme2": {ID: "org:2", Slug: "acme2"},
	}, az)
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	h.RegisterRoutes(api)
	return httptest.NewServer(router), svc
}

func itGet(t *testing.T, srv *httptest.Server, path, token string) (int, map[string]any) {
	t.Helper()
	return itDo(t, srv, http.MethodGet, path, token)
}

func itDo(t *testing.T, srv *httptest.Server, method, path, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("response not JSON: %s", raw)
		}
	}
	return resp.StatusCode, body
}

func TestPlatformResourcesHTTPEndToEnd(t *testing.T) {
	srv, svc := itServer(t, itAuthorizer{allow: true})
	const listPath = "/api/v1/tenants/acme/platform-resources"

	// Unauthenticated: 401.
	if code, _ := itGet(t, srv, listPath, ""); code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", code)
	}
	// Bad token: 401.
	if code, _ := itGet(t, srv, listPath, "bogus"); code != http.StatusUnauthorized {
		t.Errorf("bad token: status = %d, want 401", code)
	}
	// Authenticated but not an org member: 403.
	if code, _ := itGet(t, srv, listPath, "outsider"); code != http.StatusForbidden {
		t.Errorf("outsider: status = %d, want 403", code)
	}
	// Unknown org slug for a non-member: 403 (membership is checked first,
	// same as the inventory authorizeOrg pattern).
	if code, _ := itGet(t, srv, "/api/v1/tenants/nope/platform-resources", "good"); code != http.StatusForbidden {
		t.Errorf("non-member unknown org: status = %d, want 403", code)
	}
	// Member of an org slug with no tenancy record: 404.
	if code, _ := itGet(t, srv, "/api/v1/tenants/ghost/platform-resources", "ghost"); code != http.StatusNotFound {
		t.Errorf("unknown org: status = %d, want 404", code)
	}

	// Happy path: tenant with no rows gets 200 + empty array (not null).
	code, body := itGet(t, srv, listPath, "good")
	if code != http.StatusOK {
		t.Fatalf("empty list: status = %d, want 200 (body %v)", code, body)
	}
	res, ok := body["resources"].([]any)
	if !ok {
		t.Fatalf("resources = %v, want JSON array", body["resources"])
	}
	if len(res) != 0 {
		t.Errorf("resources len = %d, want 0", len(res))
	}

	// Seed one resource via the service, then list + get over HTTP.
	r, err := svc.EnsureDesired(context.Background(), "org:1",
		types.PlatformKindKeycloakRealm, "acme", json.RawMessage(`{"realm":"acme"}`))
	if err != nil {
		t.Fatal(err)
	}

	code, body = itGet(t, srv, listPath, "good")
	if code != http.StatusOK {
		t.Fatalf("list: status = %d, want 200", code)
	}
	res, _ = body["resources"].([]any)
	if len(res) != 1 {
		t.Fatalf("resources len = %d, want 1 (body %v)", len(res), body)
	}
	item, _ := res[0].(map[string]any)
	if item["id"] != r.ID {
		t.Errorf("id = %v, want %q", item["id"], r.ID)
	}
	if item["tenant"] != "org:1" {
		t.Errorf("tenant = %v, want org:1", item["tenant"])
	}
	if item["kind"] != "keycloak-realm" || item["name"] != "acme" || item["status"] != "reconciling" {
		t.Errorf("kind/name/status = %v/%v/%v", item["kind"], item["name"], item["status"])
	}
	if _, ok := item["updatedAt"].(string); !ok {
		t.Errorf("updatedAt missing or not a string: %v", item["updatedAt"])
	}
	if _, ok := item["detail"].(string); !ok {
		t.Errorf("detail missing: %v", item)
	}

	// Detail endpoint.
	code, body = itGet(t, srv, listPath+"/"+r.ID, "good")
	if code != http.StatusOK {
		t.Fatalf("get: status = %d, want 200", code)
	}
	got, _ := body["resource"].(map[string]any)
	if got["id"] != r.ID {
		t.Errorf("get id = %v, want %q", got["id"], r.ID)
	}

	// Cross-tenant get must 404 (no existence leak).
	if code, _ := itGet(t, srv, "/api/v1/tenants/acme2/platform-resources/"+r.ID, "good"); code != http.StatusNotFound {
		t.Errorf("cross-tenant get: status = %d, want 404", code)
	}
	// Unknown id: 404.
	if code, _ := itGet(t, srv, listPath+"/nope", "good"); code != http.StatusNotFound {
		t.Errorf("unknown id: status = %d, want 404", code)
	}
}

func TestPlatformResourcesReconcileEndpoint(t *testing.T) {
	queue := &itQueue{}
	srv, svc := itServerWithQueue(t, itAuthorizer{allow: true}, queue)
	const path = "/api/v1/tenants/acme/platform-resources/reconcile"
	ctx := context.Background()

	if err := svc.EnsureBaseResources(ctx, &types.Organization{ID: "org:1", Slug: "acme"}); err != nil {
		t.Fatal(err)
	}

	// Unauthenticated: 401; non-member: 403; authz-denied covered by
	// itAuthorizer{allow:false} below.
	if code, _ := itDo(t, srv, http.MethodPost, path, ""); code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", code)
	}
	if code, _ := itDo(t, srv, http.MethodPost, path, "outsider"); code != http.StatusForbidden {
		t.Errorf("outsider: status = %d, want 403", code)
	}

	code, body := itDo(t, srv, http.MethodPost, path, "good")
	if code != http.StatusAccepted {
		t.Fatalf("reconcile: status = %d, want 202 (body %v)", code, body)
	}
	if got := body["resourcesReRequested"]; got != float64(3) {
		t.Errorf("resourcesReRequested = %v, want 3", got)
	}
	if got := body["clustersNotified"]; got != float64(1) {
		t.Errorf("clustersNotified = %v, want 1", got)
	}
	if len(queue.cmds) != 1 || queue.cmds[0].ClusterID != "cluster:p1" {
		t.Fatalf("enqueued = %+v, want one resync for cluster:p1", queue.cmds)
	}

	// Authz denial → 403.
	srvDenied, _ := itServer(t, itAuthorizer{allow: false})
	if code, _ := itDo(t, srvDenied, http.MethodPost, path, "good"); code != http.StatusForbidden {
		t.Errorf("authz denied: status = %d, want 403", code)
	}
}

func TestPlatformResourcesHTTPAuthzDenied(t *testing.T) {
	srv, _ := itServer(t, itAuthorizer{allow: false})
	// Member of org, but the OpenFGA check denies: 403.
	if code, _ := itGet(t, srv, "/api/v1/tenants/acme/platform-resources", "good"); code != http.StatusForbidden {
		t.Errorf("authz denied: status = %d, want 403", code)
	}
}
