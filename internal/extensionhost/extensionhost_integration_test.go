//go:build integration

package extensionhost_test

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
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/extensionhost"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

func itService(t *testing.T) *extensionhost.Service {
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
	return extensionhost.NewService(database, extensionhost.NewStore(), audit.NewStore())
}

func TestExtensionRegistryLifecycle(t *testing.T) {
	svc := itService(t)
	ctx := context.Background()

	e, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{
		OrgID: "org:1", Name: "argocd", Version: "0.1.0", Endpoint: "http://127.0.0.1:9001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.State != types.ExtensionStatePending {
		t.Fatalf("state = %q, want pending", e.State)
	}

	got, err := svc.Get(ctx, "org:1", e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "argocd" || got.Kind != types.ExtensionKindBackend {
		t.Fatalf("got %+v", got)
	}
	if _, err := svc.Get(ctx, "org:2", e.ID); !errors.Is(err, extensionhost.ErrNotFound) {
		t.Errorf("cross-org get = %v, want ErrNotFound", err)
	}

	if err := svc.SetState(ctx, "system:extensionhost", e.ID, types.ExtensionStateReady); err != nil {
		t.Fatal(err)
	}
	got, _ = svc.Get(ctx, "org:1", e.ID)
	if got.State != types.ExtensionStateReady {
		t.Errorf("state = %q, want ready", got.State)
	}
	if err := svc.SetState(ctx, "system:extensionhost", e.ID, "bogus"); err == nil {
		t.Error("expected invalid state error")
	}

	list, err := svc.List(ctx, "org:1")
	if err != nil || len(list) != 1 {
		t.Errorf("list = %v, %v", list, err)
	}

	if err := svc.Unregister(ctx, "user-1", "org:1", e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, "org:1", e.ID); !errors.Is(err, extensionhost.ErrNotFound) {
		t.Errorf("get after unregister = %v, want ErrNotFound", err)
	}
}

func TestUiExtensionRegistryLifecycle(t *testing.T) {
	svc := itService(t)
	ctx := context.Background()

	// UI-only registration: row created with kind=ui, straight to ready.
	e, err := svc.RegisterUi(ctx, "user-1", extensionhost.RegisterUiInput{
		OrgID: "org:1", Name: "cards", Version: "0.1.0",
		RemoteEntry: "https://example.com/remoteEntry.js",
		Slots:       []types.UiSlotDescriptor{{Kind: types.UiSlotCatalogCard, Name: "cost-badge"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != types.ExtensionKindUI || e.State != types.ExtensionStateReady {
		t.Fatalf("kind/state = %q/%q", e.Kind, e.State)
	}
	if e.Ui == nil || !e.Ui.Enabled || len(e.Ui.Slots) != 1 {
		t.Fatalf("ui descriptor = %+v", e.Ui)
	}

	got, err := svc.GetUi(ctx, "org:1", "cards")
	if err != nil || got.Ui.RemoteEntry != "https://example.com/remoteEntry.js" {
		t.Fatalf("getUi = %+v, %v", got, err)
	}
	if _, err := svc.GetUi(ctx, "org:2", "cards"); !errors.Is(err, extensionhost.ErrNotFound) {
		t.Errorf("cross-org getUi = %v, want ErrNotFound", err)
	}

	// Upsert: same name re-POST updates the descriptor and version.
	e2, err := svc.RegisterUi(ctx, "user-1", extensionhost.RegisterUiInput{
		OrgID: "org:1", Name: "cards", Version: "0.2.0",
		RemoteEntryOci: "ghcr.io/7k-inari/cards-ui:0.2.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if e2.ID != e.ID {
		t.Errorf("upsert created a new row: %q != %q", e2.ID, e.ID)
	}
	if e2.Version != "0.2.0" || e2.Ui.RemoteEntryOci == "" || e2.Ui.RemoteEntry != "" {
		t.Errorf("upsert result = %+v ui=%+v", e2, e2.Ui)
	}

	list, err := svc.ListUi(ctx, "org:1")
	if err != nil || len(list) != 1 {
		t.Errorf("listUi = %v, %v", list, err)
	}

	// Paired backend: UI registration on a backend row keeps the row.
	b, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{
		OrgID: "org:1", Name: "argocd", Version: "0.1.0", Endpoint: "http://127.0.0.1:9001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterUi(ctx, "user-1", extensionhost.RegisterUiInput{
		OrgID: "org:1", Name: "argocd", Version: "0.1.0",
		RemoteEntry: "https://example.com/argocd/remoteEntry.js",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.UnregisterUi(ctx, "user-1", "org:1", "argocd"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, "org:1", b.ID); err != nil {
		t.Errorf("backend row removed with ui descriptor: %v", err)
	}

	// UI-only unregister deletes the row.
	if err := svc.UnregisterUi(ctx, "user-1", "org:1", "cards"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetUi(ctx, "org:1", "cards"); !errors.Is(err, extensionhost.ErrNotFound) {
		t.Errorf("getUi after unregister = %v, want ErrNotFound", err)
	}
}

func TestExtensionRegisterValidation(t *testing.T) {
	svc := itService(t)
	ctx := context.Background()
	if _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{OrgID: "org:1", Name: "x"}); err == nil {
		t.Error("expected version required error")
	}
	if _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{Name: "x", Version: "1"}); err == nil {
		t.Error("expected orgID required error")
	}
	if _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{
		OrgID: "org:1", Name: "x", Version: "1", Kind: "ui",
	}); err == nil {
		t.Error("expected kind error")
	}
}

// HTTP-level coverage for the UI registry routes (§5.8): the full router
// stack (bearer middleware → authorizeOrg → handler) against a real service.
type itValidator struct{ id *authn.Identity }

func (v itValidator) Validate(_ context.Context, token string) (*authn.Identity, error) {
	if token == "bad" {
		return nil, errors.New("invalid token")
	}
	return v.id, nil
}

type itRelationAuthorizer struct{ deny map[string]bool }

func (a itRelationAuthorizer) Check(_ context.Context, _, relation, _ string) (bool, error) {
	return !a.deny[relation], nil
}
func (a itRelationAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type itTenantResolver struct{ org *types.Organization }

func (r itTenantResolver) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if r.org == nil || r.org.Slug != slug {
		return nil, tenancy.ErrOrgNotFound
	}
	return r.org, nil
}

type itReady struct{}

func (itReady) Ping(context.Context) error { return nil }

func TestUiExtensionHTTPRoutes(t *testing.T) {
	svc := itService(t)
	org := &types.Organization{ID: "org:1", Slug: "acme"}
	id := &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}

	content := []byte(`/* remoteEntry */`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	}))
	t.Cleanup(upstream.Close)

	fetcher := &extensionhost.RemoteEntryFetcher{}
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), itValidator{id}, itReady{})
	extensionhost.NewHandler(svc, itTenantResolver{org}, itRelationAuthorizer{}).
		WithRemoteEntryFetcher(fetcher).RegisterRoutes(api)
	extensionhost.NewUiAssetServer(svc, itTenantResolver{org}, fetcher).Mount(router)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	base := srv.URL + "/api/v1/tenants/acme/extensions/ui"

	do := func(t *testing.T, method, url, token, body string) *http.Response {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, url, rdr)
		if err != nil {
			t.Fatal(err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	t.Run("viewer cannot register", func(t *testing.T) {
		r, api2 := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), itValidator{id}, itReady{})
		extensionhost.NewHandler(svc, itTenantResolver{org},
			itRelationAuthorizer{deny: map[string]bool{authz.RelationPlatformEngineer: true}}).RegisterRoutes(api2)
		s := httptest.NewServer(r)
		t.Cleanup(s.Close)
		req, _ := http.NewRequest(http.MethodPost, s.URL+"/api/v1/tenants/acme/extensions/ui",
			strings.NewReader(`{"name":"cards","version":"0.1.0","remoteEntry":"https://example.com/r.js"}`))
		req.Header.Set("Authorization", "Bearer good")
		req.Header.Set("Content-Type", "application/json")
		res, err := s.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", res.StatusCode)
		}
	})

	t.Run("unauthenticated rejected", func(t *testing.T) {
		res := do(t, http.MethodGet, base, "", "")
		defer res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", res.StatusCode)
		}
	})

	t.Run("non-member org rejected", func(t *testing.T) {
		res := do(t, http.MethodGet, srv.URL+"/api/v1/tenants/ghost/extensions/ui", "good", "")
		defer res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", res.StatusCode)
		}
	})

	t.Run("register validation error", func(t *testing.T) {
		res := do(t, http.MethodPost, base, "good", `{"name":"bad","version":"1"}`)
		defer res.Body.Close()
		if res.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422", res.StatusCode)
		}
	})

	t.Run("register list serve unregister", func(t *testing.T) {
		res := do(t, http.MethodPost, base, "good",
			`{"name":"cards","version":"0.1.0","remoteEntry":"`+upstream.URL+`","slots":[{"kind":"catalog-card","name":"cost-badge"}]}`)
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("register status = %d body = %s", res.StatusCode, body)
		}
		var out struct {
			Extension struct {
				Name           string `json:"name"`
				RemoteEntryURL string `json:"remoteEntryUrl"`
				Enabled        bool   `json:"enabled"`
			} `json:"extension"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		wantURL := "/api/v1/tenants/acme/extensions/ui/cards/remoteEntry.js"
		if out.Extension.RemoteEntryURL != wantURL {
			t.Errorf("remoteEntryUrl = %q, want %q", out.Extension.RemoteEntryURL, wantURL)
		}
		if !out.Extension.Enabled {
			t.Error("enabled = false, want true")
		}

		res = do(t, http.MethodGet, base, "good", "")
		body, _ = io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"cards"`) {
			t.Errorf("list status = %d body = %s", res.StatusCode, body)
		}

		// The asset route is public (Module Federation script loads carry no
		// Authorization header); it must serve the registered upstream bytes.
		res = do(t, http.MethodGet, srv.URL+wantURL, "", "")
		body, _ = io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK || string(body) != string(content) {
			t.Errorf("asset status = %d body = %q", res.StatusCode, body)
		}

		res = do(t, http.MethodDelete, base+"/cards", "good", "")
		res.Body.Close()
		if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
			t.Errorf("delete status = %d", res.StatusCode)
		}
		res = do(t, http.MethodGet, srv.URL+wantURL, "", "")
		res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("asset after delete status = %d, want 404", res.StatusCode)
		}
	})
}
