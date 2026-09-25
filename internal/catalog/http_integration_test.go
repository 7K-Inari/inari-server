//go:build integration

package catalog_test

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

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/capabilities"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type itValidator struct{}

func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "admin":
		return &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}, nil
	case "viewer":
		return &authn.Identity{Subject: "user-2", Organizations: []string{"acme"}}, nil
	case "outsider":
		return &authn.Identity{Subject: "user-9", Organizations: []string{"other"}}, nil
	}
	return nil, errors.New("invalid token")
}

// itAuthorizer grants relations per user: user-1 is org admin, user-2 viewer.
type itAuthorizer struct{}

func (itAuthorizer) Check(_ context.Context, user, relation, _ string) (bool, error) {
	switch user {
	case "user:user-1":
		return true, nil
	case "user:user-2":
		return relation == "viewer", nil
	}
	return false, nil
}
func (itAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type itTenants map[string]*types.Organization

func (t itTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if o, ok := t[slug]; ok {
		return o, nil
	}
	return nil, tenancy.ErrOrgNotFound
}

func itServer(t *testing.T) (*httptest.Server, *db.DB) {
	t.Helper()
	return itServerWithCaps(t, nil)
}

func itServerWithCaps(t *testing.T, caps catalog.CapabilityLister) (*httptest.Server, *db.DB) {
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
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1')`); err != nil {
		t.Fatal(err)
	}

	auditStore := audit.NewStore()
	catalogSvc := catalog.NewService(database, catalog.NewStore(), caps, auditStore,
		&catalog.FixturePuller{Root: "testdata/oci"})
	if _, err := catalogSvc.Sync(ctx); err != nil {
		t.Fatalf("catalog sync: %v", err)
	}

	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	catalog.NewHandler(catalogSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{}).RegisterRoutes(api)
	return httptest.NewServer(router), database
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

type visList struct {
	Items []catalog.OrgVisibilityEntry `json:"items"`
}

func visEntry(t *testing.T, srv *httptest.Server, token, itemID string) catalog.OrgVisibilityEntry {
	t.Helper()
	code, body := itReq(t, srv, "GET", "/api/v1/tenants/acme/catalog-visibility", token, "")
	if code != http.StatusOK {
		t.Fatalf("list visibility: %d %s", code, body)
	}
	var out visList
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	for _, e := range out.Items {
		if e.ItemID == itemID {
			return e
		}
	}
	t.Fatalf("item %s missing from visibility list: %s", itemID, body)
	return catalog.OrgVisibilityEntry{}
}

type catalogList struct {
	Items []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Source   string `json:"source"`
		Category string `json:"category"`
	} `json:"items"`
	Total int `json:"total"`
}

func itListCatalog(t *testing.T, srv *httptest.Server, query string) catalogList {
	t.Helper()
	code, body := itReq(t, srv, "GET", "/api/v1/tenants/acme/catalog"+query, "viewer", "")
	if code != http.StatusOK {
		t.Fatalf("GET catalog%s: %d %s", query, code, body)
	}
	var out catalogList
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestListCatalogFiltering(t *testing.T) {
	srv, _ := itServer(t)
	defer srv.Close()

	all := itListCatalog(t, srv, "")
	if all.Total != len(all.Items) || all.Total < 2 {
		t.Fatalf("unfiltered: total=%d items=%d", all.Total, len(all.Items))
	}

	// Free-text search matches name/display name/description.
	got := itListCatalog(t, srv, "?q=postgres")
	if got.Total != 1 || got.Items[0].Name != "postgres-aws" {
		t.Errorf("q=postgres = %+v", got)
	}
	if got := itListCatalog(t, srv, "?q=nomatch"); got.Total != 0 || len(got.Items) != 0 {
		t.Errorf("q=nomatch = %+v", got)
	}
	// ILIKE wildcards in q are escaped, not treated as patterns.
	if got := itListCatalog(t, srv, "?q=%25"); got.Total != 0 {
		t.Errorf("q=%% total = %d, want 0 (literal %% matches nothing)", got.Total)
	}

	// Source and category facets.
	if got := itListCatalog(t, srv, "?source=curated"); got.Total != 2 {
		t.Errorf("source=curated total = %d, want 2 (both fixture packages)", got.Total)
	}
	got = itListCatalog(t, srv, "?category=database")
	if got.Total != 1 || got.Items[0].Category != "database" {
		t.Errorf("category=database = %+v", got)
	}
	if got := itListCatalog(t, srv, "?category=bogus"); got.Total != 0 {
		t.Errorf("category=bogus total = %d, want 0", got.Total)
	}

	// Sort: name descending reverses the default order.
	asc := itListCatalog(t, srv, "?sort=name")
	desc := itListCatalog(t, srv, "?sort=name-desc")
	if asc.Items[0].Name != desc.Items[len(desc.Items)-1].Name {
		t.Errorf("name-desc is not the reverse of name: %v vs %v", asc.Items, desc.Items)
	}

	// Pagination slices the sorted result; total stays un-paginated.
	page := itListCatalog(t, srv, "?limit=1&offset=1")
	if page.Total != all.Total || len(page.Items) != 1 || page.Items[0].Name != all.Items[1].Name {
		t.Errorf("limit=1&offset=1 = %+v, want second of %v", page, all.Items)
	}
	if got := itListCatalog(t, srv, "?offset=999"); got.Total != all.Total || len(got.Items) != 0 {
		t.Errorf("offset past end = %+v", got)
	}

	// Invalid enum values are rejected by huma validation.
	if code, _ := itReq(t, srv, "GET", "/api/v1/tenants/acme/catalog?sort=name;DROP", "viewer", ""); code != http.StatusUnprocessableEntity {
		t.Errorf("sort injection: got %d, want 422", code)
	}
	if code, _ := itReq(t, srv, "GET", "/api/v1/tenants/acme/catalog?source=bogus", "viewer", ""); code != http.StatusUnprocessableEntity {
		t.Errorf("bogus source: got %d, want 422", code)
	}
}

// Discovered projections merge with persisted items before filtering,
// sorting, and pagination — the "what can I run here?" path (ADR-0009).
func TestListCatalogDiscoveredMerge(t *testing.T) {
	srv, database := itServerWithCaps(t, capabilities.NewStore())
	defer srv.Close()
	ctx := context.Background()

	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO clusters (id, org_id, name, state) VALUES ('cl-1','org:1','eks-prod','active')`); err != nil {
		t.Fatal(err)
	}
	caps := capabilities.NewStore()
	for _, item := range []types.CapabilityItem{
		{Kind: types.CapabilityKindCRD, Name: "aardvark", Group: "example.io", Version: "v1"},
		{Kind: types.CapabilityKindCRD, Name: "zebra", Group: "example.io", Version: "v1"},
	} {
		if err := caps.Upsert(ctx, database.Pool, "cl-1", item); err != nil {
			t.Fatal(err)
		}
	}

	// Merged: persisted fixture items plus the two discovered projections.
	plain := itListCatalog(t, srv, "")
	merged := itListCatalog(t, srv, "?cluster=cl-1")
	if merged.Total != plain.Total+2 {
		t.Fatalf("merged total = %d, want %d (persisted %d + 2 discovered)", merged.Total, plain.Total+2, plain.Total)
	}

	// Facets apply to projections: source filter isolates them.
	got := itListCatalog(t, srv, "?cluster=cl-1&source=discovered")
	if got.Total != 2 {
		t.Errorf("source=discovered total = %d, want 2 (%+v)", got.Total, got.Items)
	}
	// Projections have no category: excluded when a category filter is active.
	if got := itListCatalog(t, srv, "?cluster=cl-1&category=database"); got.Total != 1 {
		t.Errorf("category=database with cluster total = %d, want 1", got.Total)
	}
	// Free-text search reaches projection names.
	if got := itListCatalog(t, srv, "?cluster=cl-1&q=aardvark"); got.Total != 1 {
		t.Errorf("q=aardvark total = %d, want 1", got.Total)
	}

	// Pagination slices the merged, sorted result; total stays un-paginated.
	page := itListCatalog(t, srv, "?cluster=cl-1&limit=1&offset=0")
	if page.Total != merged.Total || len(page.Items) != 1 || page.Items[0].Name != "aardvark.example.io" {
		t.Errorf("first merged page = %+v, want aardvark.example.io of %d", page, merged.Total)
	}

	// Without the cluster param nothing leaks into other clusters' views.
	if got := itListCatalog(t, srv, "?cluster=cl-unknown"); got.Total != plain.Total {
		t.Errorf("unknown cluster total = %d, want %d", got.Total, plain.Total)
	}
}

func TestOrgVisibilityOverlay(t *testing.T) {
	srv, database := itServer(t)
	defer srv.Close()
	ctx := context.Background()
	const item = "curated:postgres-aws"

	// Default: no overlay row, platform-public → visible.
	if e := visEntry(t, srv, "viewer", item); !e.Visible || e.OrgHidden || e.PlatformHidden {
		t.Fatalf("default entry = %+v, want visible", e)
	}

	// Viewer cannot write.
	if code, _ := itReq(t, srv, "PUT", "/api/v1/tenants/acme/catalog-visibility/"+item, "viewer", `{"visible":false}`); code != http.StatusForbidden {
		t.Errorf("viewer PUT: got %d, want 403", code)
	}

	// Admin hides the item.
	if code, body := itReq(t, srv, "PUT", "/api/v1/tenants/acme/catalog-visibility/"+item, "admin", `{"visible":false}`); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("admin hide: %d %s", code, body)
	}
	if e := visEntry(t, srv, "viewer", item); e.Visible || !e.OrgHidden || e.PlatformHidden {
		t.Errorf("after hide entry = %+v, want org-hidden", e)
	}

	// Audit row carries before/after.
	var action string
	var payload []byte
	err := database.Pool.QueryRow(ctx,
		`SELECT action, payload FROM audit_events WHERE object_id = $1 AND action = 'catalog.visibility.changed' ORDER BY id DESC LIMIT 1`,
		item).Scan(&action, &payload)
	if err != nil {
		t.Fatalf("audit row: %v", err)
	}
	var p types.CatalogVisibilityPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.OrgID != "org:1" || p.ItemID != item || !p.Before || p.After {
		t.Errorf("audit payload = %+v, want before=true after=false", p)
	}

	// Re-showing restores effective visibility.
	if code, body := itReq(t, srv, "PUT", "/api/v1/tenants/acme/catalog-visibility/"+item, "admin", `{"visible":true}`); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("admin show: %d %s", code, body)
	}
	if e := visEntry(t, srv, "viewer", item); !e.Visible {
		t.Errorf("after show entry = %+v, want visible", e)
	}

	// Platform-hidden items stay hidden even when the org shows them.
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO catalog_visibility (item_id, org_id, cluster_id) VALUES ($1,'org:other','*')`, item); err != nil {
		t.Fatal(err)
	}
	if code, body := itReq(t, srv, "PUT", "/api/v1/tenants/acme/catalog-visibility/"+item, "admin", `{"visible":true}`); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("admin show platform-hidden: %d %s", code, body)
	}
	if e := visEntry(t, srv, "viewer", item); e.Visible || !e.PlatformHidden || e.OrgHidden {
		t.Errorf("platform-hidden entry = %+v, want hidden by platform only", e)
	}

	// Error ladder: outsider, unknown org, unknown item.
	if code, _ := itReq(t, srv, "GET", "/api/v1/tenants/acme/catalog-visibility", "outsider", ""); code != http.StatusForbidden {
		t.Errorf("outsider GET: got %d, want 403", code)
	}
	if code, _ := itReq(t, srv, "GET", "/api/v1/tenants/acme/catalog-visibility", "", ""); code != http.StatusUnauthorized {
		t.Errorf("no token GET: got %d, want 401", code)
	}
	if code, _ := itReq(t, srv, "PUT", "/api/v1/tenants/acme/catalog-visibility/curated:nope", "admin", `{"visible":false}`); code != http.StatusNotFound {
		t.Errorf("unknown item PUT: got %d, want 404", code)
	}
}
