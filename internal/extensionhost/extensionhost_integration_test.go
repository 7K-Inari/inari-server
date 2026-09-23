//go:build integration

package extensionhost_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func itDB(t *testing.T) *db.DB {
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
	return database
}

func seedOrg(t *testing.T, database *db.DB, id string) {
	t.Helper()
	if _, err := database.Pool.Exec(context.Background(),
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ($1,'acme','Acme','kc-1')`, id); err != nil {
		t.Fatal(err)
	}
}

func itService(t *testing.T) *extensionhost.Service {
	t.Helper()
	database := itDB(t)
	seedOrg(t, database, "org:1")
	return extensionhost.NewService(database, extensionhost.NewStore(), audit.NewStore())
}

func TestExtensionRegistryLifecycle(t *testing.T) {
	svc := itService(t)
	ctx := context.Background()

	e, _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{
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

	// Upsert without an enabled flag preserves the stored value (no silent
	// re-enable of a disabled extension).
	disabled := false
	e3, err := svc.RegisterUi(ctx, "user-1", extensionhost.RegisterUiInput{
		OrgID: "org:1", Name: "cards", Version: "0.2.1",
		RemoteEntryOci: "ghcr.io/7k-inari/cards-ui:0.2.1", Enabled: &disabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if e3.Ui.Enabled {
		t.Fatal("explicit enabled=false not stored")
	}
	e4, err := svc.RegisterUi(ctx, "user-1", extensionhost.RegisterUiInput{
		OrgID: "org:1", Name: "cards", Version: "0.2.2",
		RemoteEntryOci: "ghcr.io/7k-inari/cards-ui:0.2.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if e4.Ui.Enabled {
		t.Error("upsert with omitted enabled silently re-enabled the extension")
	}

	// Paired backend: UI registration on a backend row keeps the row.
	b, _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{
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
	if _, _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{OrgID: "org:1", Name: "x"}); err == nil {
		t.Error("expected version required error")
	}
	if _, _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{Name: "x", Version: "1"}); err == nil {
		t.Error("expected orgID required error")
	}
	if _, _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{
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

type itRelationAuthorizer struct {
	deny map[string]bool
	// invokeObjects, when non-nil, gates RelationInvoke checks per object.
	invokeObjects map[string]bool
}

func (a itRelationAuthorizer) Check(_ context.Context, _, relation, object string) (bool, error) {
	if relation == authz.RelationInvoke && a.invokeObjects != nil {
		return a.invokeObjects[object], nil
	}
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

	t.Run("self extension permissions reflect FGA invoke", func(t *testing.T) {
		ctx := context.Background()
		if _, err := svc.RegisterUi(ctx, "user-1", extensionhost.RegisterUiInput{
			OrgID: "org:1", Name: "allowed-ext", Version: "1", RemoteEntry: "https://example.com/a.js",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.RegisterUi(ctx, "user-1", extensionhost.RegisterUiInput{
			OrgID: "org:1", Name: "denied-ext", Version: "1", RemoteEntry: "https://example.com/b.js",
		}); err != nil {
			t.Fatal(err)
		}
		allowed, err := svc.GetUi(ctx, "org:1", "allowed-ext")
		if err != nil {
			t.Fatal(err)
		}
		r, api2 := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), itValidator{id}, itReady{})
		extensionhost.NewHandler(svc, itTenantResolver{org}, itRelationAuthorizer{
			invokeObjects: map[string]bool{authz.ExtensionObject(allowed.ID): true},
		}).RegisterRoutes(api2)
		s := httptest.NewServer(r)
		t.Cleanup(s.Close)
		req, _ := http.NewRequest(http.MethodGet, s.URL+"/api/v1/tenants/acme/authz/self/extensions", nil)
		req.Header.Set("Authorization", "Bearer good")
		res, err := s.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d body = %s", res.StatusCode, body)
		}
		var out struct {
			Permissions []string `json:"permissions"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Permissions) != 1 || out.Permissions[0] != "extensions:invoke:allowed-ext" {
			t.Errorf("permissions = %v, want [extensions:invoke:allowed-ext]", out.Permissions)
		}
	})
}

// fakeExtensionClients fakes the Keycloak client CRUD seam (identity
// lifecycle assertions without a realm).
type fakeExtensionClients struct {
	created  []tenancy.ClientSpec
	rotated  []string
	disabled []string
	secretN  int
}

func (f *fakeExtensionClients) CreateClient(_ context.Context, spec tenancy.ClientSpec) (string, error) {
	f.created = append(f.created, spec)
	f.secretN++
	return fmt.Sprintf("secret-%d", f.secretN), nil
}
func (f *fakeExtensionClients) RotateClientSecret(_ context.Context, clientID string) (string, error) {
	f.rotated = append(f.rotated, clientID)
	f.secretN++
	return fmt.Sprintf("secret-%d", f.secretN), nil
}
func (f *fakeExtensionClients) DisableClient(_ context.Context, clientID string) error {
	f.disabled = append(f.disabled, clientID)
	return nil
}

// Per-extension identity lifecycle (ADR-0008): register provisions a
// service-account client and returns the secret once, rotate regenerates it,
// unregister disables the client.
func TestExtensionIdentityLifecycle(t *testing.T) {
	database := itDB(t)
	seedOrg(t, database, "org:1")
	svc := extensionhost.NewService(database, extensionhost.NewStore(), audit.NewStore())
	clients := &fakeExtensionClients{}
	svc.WithExtensionClientManager(clients, "inari-extension-gateway")
	ctx := context.Background()

	e, creds, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{
		OrgID: "org:1", Name: "argocd", Version: "0.1.0", Endpoint: "http://127.0.0.1:9001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if creds == nil || creds.ClientID != "ext-argocd" || creds.Secret != "secret-1" {
		t.Fatalf("creds = %+v", creds)
	}
	if len(clients.created) != 1 {
		t.Fatalf("created = %+v", clients.created)
	}
	spec := clients.created[0]
	if spec.ClientType != tenancy.ClientTypeService || len(spec.Audiences) != 1 ||
		spec.Audiences[0] != "inari-extension-gateway" {
		t.Fatalf("spec = %+v", spec)
	}

	got, err := svc.GetByClientID(ctx, "ext-argocd")
	if err != nil || got.ID != e.ID {
		t.Fatalf("GetByClientID = %+v, %v", got, err)
	}
	rot, err := svc.RotateIdentitySecret(ctx, "user-1", "org:1", e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rot.Secret != "secret-2" || clients.rotated[0] != "ext-argocd" {
		t.Fatalf("rotate = %+v, rotated = %v", rot, clients.rotated)
	}

	if err := svc.Unregister(ctx, "user-1", "org:1", e.ID); err != nil {
		t.Fatal(err)
	}
	if len(clients.disabled) != 1 || clients.disabled[0] != "ext-argocd" {
		t.Fatalf("disabled = %v", clients.disabled)
	}
}

// Without a wired client manager, register provisions no identity (dev/fake
// mode) and returns nil credentials.
func TestExtensionRegisterWithoutIdentityManager(t *testing.T) {
	svc := itService(t)
	_, creds, err := svc.Register(context.Background(), "user-1", extensionhost.RegisterInput{
		OrgID: "org:1", Name: "argocd", Version: "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if creds != nil {
		t.Fatalf("creds = %+v, want nil", creds)
	}
}
