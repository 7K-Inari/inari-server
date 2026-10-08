//go:build integration

package featureflags

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

	"github.com/open-feature/go-sdk/openfeature"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/cache"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

func itDB(t *testing.T) *db.DB {
	t.Helper()
	pg, err := testutil.SharedPostgres(context.Background())
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	return database
}

func itCache(t *testing.T) cache.Cache {
	t.Helper()
	c, err := cache.New(cache.Config{Backend: "memory", MemoryMaxEntries: 1000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// TestStoreCRUD exercises the flag row lifecycle against a migrated DB
// (migration 0032 included).
func TestStoreCRUD(t *testing.T) {
	database := itDB(t)
	store := NewStore()
	ctx := context.Background()

	row, err := store.Get(ctx, database.Pool, KeyKubectlAccessEnabled, ScopePlatform, "")
	if err != nil || row != nil {
		t.Fatalf("empty Get = %v, %v; want nil row", row, err)
	}

	in := Row{FlagKey: KeyKubectlAccessEnabled, Scope: ScopePlatform, Value: false, UpdatedBy: "admin"}
	if err := store.Upsert(ctx, database.Pool, in); err != nil {
		t.Fatal(err)
	}
	row, err = store.Get(ctx, database.Pool, KeyKubectlAccessEnabled, ScopePlatform, "")
	if err != nil || row == nil || row.Value != false || row.UpdatedBy != "admin" {
		t.Fatalf("Get after Upsert = %+v, %v", row, err)
	}

	// Overwrite + cluster override coexistence.
	in.Value = true
	if err := store.Upsert(ctx, database.Pool, in); err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(ctx, database.Pool, Row{FlagKey: KeyKubectlAccessEnabled, Scope: ScopeCluster, ScopeKey: "clu-1", Value: false, UpdatedBy: "op"}); err != nil {
		t.Fatal(err)
	}
	rows, err := store.List(ctx, database.Pool, KeyKubectlAccessEnabled)
	if err != nil || len(rows) != 2 {
		t.Fatalf("List = %+v, %v; want 2 rows", rows, err)
	}
	if rows[0].Scope != ScopePlatform {
		t.Errorf("List order: first row scope = %q, want platform", rows[0].Scope)
	}

	deleted, err := store.Delete(ctx, database.Pool, KeyKubectlAccessEnabled, ScopeCluster, "clu-1")
	if err != nil || !deleted {
		t.Fatalf("Delete = %v, %v; want deleted", deleted, err)
	}
	deleted, err = store.Delete(ctx, database.Pool, KeyKubectlAccessEnabled, ScopeCluster, "clu-1")
	if err != nil || deleted {
		t.Fatalf("second Delete = %v, %v; want not deleted", deleted, err)
	}
}

// TestServiceWritesAuditAndOutbox proves Set/Clear persist the flag, an
// audit row, and an outbox row in one transaction.
func TestServiceWritesAuditAndOutbox(t *testing.T) {
	database := itDB(t)
	svc := NewService(database, NewStore(), audit.NewStore(), itCache(t), "memory")
	ctx := context.Background()

	if err := svc.Set(ctx, "admin-1", "", KeyKubectlAccessEnabled, ScopePlatform, "", false); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'featureflags.set' AND object_id = 'kubectl_access.enabled/platform/'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("audit rows = %d, want 1", n)
	}
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE event_type = 'featureflags.updated'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("outbox rows = %d, want 1", n)
	}

	if err := svc.Clear(ctx, "admin-1", "", KeyKubectlAccessEnabled, ScopePlatform, ""); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE event_type = 'featureflags.updated'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("outbox rows after clear = %d, want 2", n)
	}

	// Validation: unknown flag, wrong scope.
	if err := svc.Set(ctx, "a", "", "nope.flag", ScopePlatform, "", true); !errors.Is(err, ErrUnknownFlag) {
		t.Errorf("unknown flag err = %v, want ErrUnknownFlag", err)
	}
}

// TestProviderResolutionMatrix proves cluster override > platform row >
// built-in default, through the OpenFeature client.
func TestProviderResolutionMatrix(t *testing.T) {
	database := itDB(t)
	store := NewStore()
	svc := NewService(database, store, audit.NewStore(), itCache(t), "memory")
	ctx := context.Background()

	newClient := func(domain string) *openfeature.Client {
		t.Helper()
		if err := openfeature.SetNamedProviderAndWait(domain,
			NewDBProvider(database.Pool, store, nil, "memory", time.Minute)); err != nil {
			t.Fatal(err)
		}
		return openfeature.NewClient(domain)
	}
	eval := func(c *openfeature.Client, clusterID string) bool {
		t.Helper()
		attrs := map[string]any{}
		key := ""
		if clusterID != "" {
			key = clusterID
			attrs = map[string]any{AttrScope: string(ScopeCluster), AttrClusterID: clusterID}
		}
		v, err := c.BooleanValueDetails(ctx, KeyKubectlAccessEnabled, true, openfeature.NewEvaluationContext(key, attrs))
		if err != nil {
			t.Fatal(err)
		}
		return v.Value
	}

	client := newClient("it-matrix")
	if !eval(client, "") || !eval(client, "clu-1") {
		t.Fatal("no rows: built-in default true must apply at both scopes")
	}
	if err := svc.Set(ctx, "admin", "", KeyKubectlAccessEnabled, ScopePlatform, "", false); err != nil {
		t.Fatal(err)
	}
	// Fresh client → fresh provider (no stale cache): sees the write.
	if eval(newClient("it-matrix-2"), "") || eval(newClient("it-matrix-3"), "clu-1") {
		t.Fatal("platform false must win when no cluster override exists")
	}
	if err := svc.Set(ctx, "op", "org:1", KeyKubectlAccessEnabled, ScopeCluster, "clu-1", true); err != nil {
		t.Fatal(err)
	}
	if !eval(newClient("it-matrix-4"), "clu-1") {
		t.Error("cluster override true must beat platform false")
	}
	if eval(newClient("it-matrix-5"), "clu-2") {
		t.Error("other clusters stay at platform false")
	}
	if err := svc.Clear(ctx, "op", "org:1", KeyKubectlAccessEnabled, ScopeCluster, "clu-1"); err != nil {
		t.Fatal(err)
	}
	if eval(newClient("it-matrix-6"), "clu-1") {
		t.Error("after clear, cluster falls back to platform false")
	}
}

// TestProviderCacheGenerationBump proves a flag write invalidates cached
// reads across provider instances sharing one cache backend (multi-replica
// propagation).
func TestProviderCacheGenerationBump(t *testing.T) {
	database := itDB(t)
	store := NewStore()
	shared := itCache(t)
	svc := NewService(database, store, audit.NewStore(), shared, "memory")
	ctx := context.Background()

	reader := NewDBProvider(database.Pool, store, shared, "memory", time.Hour)
	eval := func(clusterID string) bool {
		d := reader.BooleanEvaluation(ctx, KeyKubectlAccessEnabled, true, openfeature.FlattenedContext{
			AttrScope: string(ScopeCluster), AttrClusterID: clusterID,
		})
		return d.Value
	}
	if !eval("clu-1") {
		t.Fatal("default true expected")
	}
	if err := svc.Set(ctx, "admin", "", KeyKubectlAccessEnabled, ScopeCluster, "clu-1", false); err != nil {
		t.Fatal(err)
	}
	// Same reader instance, same cache: the write's generation bump must
	// invalidate the cached true despite the hour TTL.
	if eval("clu-1") {
		t.Error("stale cached value after flag write — generation bump failed")
	}
}

// --- HTTP surface ---

type itValidator struct{}

func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "good":
		return &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}, nil
	case "platform-admin":
		return &authn.Identity{Subject: "root-1", Organizations: nil}, nil
	}
	return nil, errors.New("invalid token")
}

// itAuthorizer maps (subject, relation) to decisions: root-1 is platform
// admin; user-1 gets the operator bundle relations.
type itAuthorizer struct{}

func (itAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	if user == authz.UserObject("root-1") {
		return relation == authz.RelationOrgCreator && object == authz.ObjectPlatform, nil
	}
	return relation == authz.RelationTenantRead || relation == authz.RelationClustersRegister, nil
}
func (itAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

// itViewerAuthorizer grants tenant.read only (viewer persona).
type itViewerAuthorizer struct{}

func (itViewerAuthorizer) Check(_ context.Context, _, relation, _ string) (bool, error) {
	return relation == authz.RelationTenantRead, nil
}
func (itViewerAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type itTenants map[string]*types.Organization

func (m itTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if o, ok := m[slug]; ok {
		return o, nil
	}
	return nil, tenancy.ErrOrgNotFound
}

func itHTTPServer(t *testing.T, az authz.Authorizer, env map[string]bool) (*httptest.Server, *db.DB, cache.Cache) {
	t.Helper()
	database := itDB(t)
	ctx := context.Background()
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO clusters (id, org_id, name, state) VALUES ('clu-1','org:1','prod','active')`); err != nil {
		t.Fatal(err)
	}
	shared := itCache(t)
	store := NewStore()
	svc := NewService(database, store, audit.NewStore(), shared, "memory")
	if err := openfeature.SetNamedProviderAndWait(t.Name(),
		NewDBProvider(database.Pool, store, shared, "memory", time.Minute)); err != nil {
		t.Fatal(err)
	}
	resolver := NewResolver(openfeature.NewClient(t.Name()), env)
	h := NewHandler(svc, resolver, itTenants{"acme": {ID: "org:1", Slug: "acme"}},
		clusterGetter{database}, az, env)
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	h.RegisterRoutes(api)
	return httptest.NewServer(router), database, shared
}

// clusterGetter adapts a *db.DB to ClusterGetter without importing
// clusterregistry (the real wiring passes clusterregistry.Service).
type clusterGetter struct{ database *db.DB }

func (g clusterGetter) GetCluster(ctx context.Context, id string) (*types.Cluster, error) {
	var c types.Cluster
	err := g.database.Pool.QueryRow(ctx, `SELECT id, org_id, name, state::text FROM clusters WHERE id = $1`, id).
		Scan(&c.ID, &c.OrgID, &c.Name, &c.State)
	if err != nil {
		return nil, err
	}
	return &c, nil
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
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestHTTPPlatformFlagLifecycle(t *testing.T) {
	srv, _, _ := itHTTPServer(t, itAuthorizer{}, nil)

	code, body := itReq(t, srv, "GET", "/api/v1/platform/feature-flags", "platform-admin", "")
	if code != 200 {
		t.Fatalf("list: %d %s", code, body)
	}
	var out struct {
		Flags []FlagView `json:"flags"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Flags) != 1 || out.Flags[0].Key != KeyKubectlAccessEnabled || !out.Flags[0].Value || out.Flags[0].Overridden {
		t.Fatalf("catalog = %+v, want kubectl_access.enabled effective true not overridden", out.Flags)
	}

	code, body = itReq(t, srv, "PUT", "/api/v1/platform/feature-flags/"+KeyKubectlAccessEnabled, "platform-admin", `{"value":false}`)
	if code != 204 && code != 200 {
		t.Fatalf("set: %d %s", code, body)
	}
	code, body = itReq(t, srv, "GET", "/api/v1/platform/feature-flags", "platform-admin", "")
	if code != 200 {
		t.Fatalf("list: %d %s", code, body)
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Flags[0].Value || !out.Flags[0].Overridden {
		t.Errorf("after set: %+v, want value false overridden", out.Flags[0])
	}

	code, body = itReq(t, srv, "DELETE", "/api/v1/platform/feature-flags/"+KeyKubectlAccessEnabled, "platform-admin", "")
	if code != 204 && code != 200 {
		t.Fatalf("clear: %d %s", code, body)
	}
	code, body = itReq(t, srv, "GET", "/api/v1/platform/feature-flags", "platform-admin", "")
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Flags[0].Value || out.Flags[0].Overridden {
		t.Errorf("after clear: %+v, want default true not overridden", out.Flags[0])
	}

	// Unknown flag 404; non-admin denied.
	code, _ = itReq(t, srv, "PUT", "/api/v1/platform/feature-flags/nope", "platform-admin", `{"value":true}`)
	if code != 404 {
		t.Errorf("unknown flag: %d, want 404", code)
	}
	code, _ = itReq(t, srv, "GET", "/api/v1/platform/feature-flags", "good", "")
	if code != 403 {
		t.Errorf("non-admin list: %d, want 403", code)
	}
}

func TestHTTPEnvPinnedSurfaces(t *testing.T) {
	env := map[string]bool{KeyKubectlAccessEnabled: true}
	srv, _, _ := itHTTPServer(t, itAuthorizer{}, env)
	code, body := itReq(t, srv, "GET", "/api/v1/platform/feature-flags", "platform-admin", "")
	if code != 200 {
		t.Fatalf("list: %d %s", code, body)
	}
	var out struct {
		Flags []FlagView `json:"flags"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Flags[0].EnvPinned {
		t.Errorf("envPinned = false with INARI_KUBECTL_ACCESS_ENABLED explicitly set")
	}
}

func TestHTTPClusterFlagLifecycle(t *testing.T) {
	srv, _, _ := itHTTPServer(t, itAuthorizer{}, nil)
	base := "/api/v1/tenants/acme/clusters/clu-1/feature-flags"

	// Tenant operator sets a cluster override.
	code, body := itReq(t, srv, "PUT", base+"/"+KeyKubectlAccessEnabled, "good", `{"value":false}`)
	if code != 204 && code != 200 {
		t.Fatalf("set: %d %s", code, body)
	}
	code, body = itReq(t, srv, "GET", base, "good", "")
	if code != 200 {
		t.Fatalf("list: %d %s", code, body)
	}
	var out struct {
		Flags []FlagView `json:"flags"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Flags) != 1 || out.Flags[0].Value || !out.Flags[0].Overridden {
		t.Errorf("cluster list = %+v, want kubectl_access.enabled false overridden", out.Flags)
	}

	code, body = itReq(t, srv, "DELETE", base+"/"+KeyKubectlAccessEnabled, "good", "")
	if code != 204 && code != 200 {
		t.Fatalf("clear: %d %s", code, body)
	}

	// Cross-tenant cluster id → 404; viewer may read but not write.
	code, _ = itReq(t, srv, "PUT", "/api/v1/tenants/acme/clusters/clu-other/feature-flags/"+KeyKubectlAccessEnabled, "good", `{"value":false}`)
	if code != 404 {
		t.Errorf("unknown cluster: %d, want 404", code)
	}
}

func TestHTTPClusterFlagViewerDenied(t *testing.T) {
	srv, _, _ := itHTTPServer(t, itViewerAuthorizer{}, nil)
	base := "/api/v1/tenants/acme/clusters/clu-1/feature-flags"
	code, body := itReq(t, srv, "GET", base, "good", "")
	if code != 200 {
		t.Fatalf("viewer read: %d %s", code, body)
	}
	code, _ = itReq(t, srv, "PUT", base+"/"+KeyKubectlAccessEnabled, "good", `{"value":false}`)
	if code != 403 {
		t.Errorf("viewer write: %d, want 403", code)
	}
}
