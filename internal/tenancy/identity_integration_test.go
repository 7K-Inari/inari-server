//go:build integration

package tenancy_test

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
	"sync"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/config"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeClientManager fakes the Keycloak client CRUD; secrets rotate on demand.
type fakeClientManager struct {
	mu       sync.Mutex
	clients  map[string]*tenancy.ClientSpec
	disabled []string
	secretN  int
}

func newFakeClientManager() *fakeClientManager {
	return &fakeClientManager{clients: map[string]*tenancy.ClientSpec{}}
}

func (f *fakeClientManager) CreateClient(_ context.Context, spec tenancy.ClientSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[spec.ClientID]; ok {
		return "", fmt.Errorf("client %s exists", spec.ClientID)
	}
	cp := spec
	f.clients[spec.ClientID] = &cp
	if spec.ClientType == tenancy.ClientTypePublic {
		return "", nil
	}
	return "secret-1", nil
}

func (f *fakeClientManager) GetClient(_ context.Context, clientID string) (*tenancy.ClientSpec, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clients[clientID], nil
}

func (f *fakeClientManager) UpdateClient(_ context.Context, spec tenancy.ClientSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[spec.ClientID]; !ok {
		return fmt.Errorf("client %s not found", spec.ClientID)
	}
	cp := spec
	f.clients[spec.ClientID] = &cp
	return nil
}

func (f *fakeClientManager) DisableClient(_ context.Context, clientID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disabled = append(f.disabled, clientID)
	return nil
}

func (f *fakeClientManager) RotateClientSecret(_ context.Context, clientID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[clientID]; !ok {
		return "", fmt.Errorf("client %s not found", clientID)
	}
	f.secretN++
	return fmt.Sprintf("rotated-%d", f.secretN), nil
}

func setupIdentitySvc(t *testing.T) (*db.DB, *tenancy.Service, *fakeClientManager, context.Context) {
	t.Helper()
	database := setupDB(t)
	ctx := context.Background()
	cm := newFakeClientManager()
	svc := tenancy.NewService(database, newFakeIdP(), tenancy.NewStore(), audit.NewStore()).
		WithClientManager(cm)
	return database, svc, cm, ctx
}

func TestIdentityClientLifecycle(t *testing.T) {
	database, svc, cm, ctx := setupIdentitySvc(t)
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}

	client, secret, err := svc.CreateIdentityClient(ctx, "user-1", "acme", &types.IdentityClient{
		Name:      "ci-bot",
		Type:      types.IdentityClientTypeService,
		Audiences: []string{"inari-server"},
		Scopes:    []string{"read"},
	})
	if err != nil {
		t.Fatalf("CreateIdentityClient: %v", err)
	}
	if client.ClientID != "org-acme-ci-bot" {
		t.Errorf("clientID = %q", client.ClientID)
	}
	if secret != "secret-1" {
		t.Errorf("secret = %q, want secret-1", secret)
	}
	if cm.clients["org-acme-ci-bot"] == nil {
		t.Error("keycloak client not created")
	}

	// Duplicate name conflicts.
	if _, _, err := svc.CreateIdentityClient(ctx, "user-1", "acme", &types.IdentityClient{
		Name: "ci-bot", Type: types.IdentityClientTypeService,
	}); !errors.Is(err, tenancy.ErrClientNameTaken) {
		t.Errorf("duplicate err = %v, want ErrClientNameTaken", err)
	}

	// Public clients return no secret.
	pub, pubSecret, err := svc.CreateIdentityClient(ctx, "user-1", "acme", &types.IdentityClient{
		Name:         "web",
		Type:         types.IdentityClientTypePublic,
		RedirectURIs: []string{"https://app.example.com/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if pubSecret != "" {
		t.Errorf("public client secret = %q, want empty", pubSecret)
	}

	list, err := svc.ListIdentityClients(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("list = %d, want 2", len(list))
	}

	// Update flows through Keycloak and the projection.
	client.Scopes = []string{"read", "deploy"}
	if err := svc.UpdateIdentityClient(ctx, "user-1", "acme", client); err != nil {
		t.Fatalf("UpdateIdentityClient: %v", err)
	}
	if got := cm.clients["org-acme-ci-bot"].Scopes; len(got) != 2 {
		t.Errorf("keycloak scopes = %v", got)
	}
	reloaded, err := svc.GetIdentityClient(ctx, "acme", "org-acme-ci-bot")
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Scopes) != 2 || reloaded.Scopes[1] != "deploy" {
		t.Errorf("db scopes = %v", reloaded.Scopes)
	}

	// Rotate returns a new secret once and audits it.
	newSecret, err := svc.RotateIdentityClientSecret(ctx, "user-1", "acme", "org-acme-ci-bot")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newSecret != "rotated-1" {
		t.Errorf("newSecret = %q", newSecret)
	}
	// Public clients have no secret to rotate.
	if _, err := svc.RotateIdentityClientSecret(ctx, "user-1", "acme", pub.ClientID); err == nil {
		t.Error("expected error rotating a public client secret")
	}

	// Disable marks the projection and calls Keycloak.
	if err := svc.DisableIdentityClient(ctx, "user-1", "acme", "org-acme-ci-bot"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if len(cm.disabled) != 1 || cm.disabled[0] != "org-acme-ci-bot" {
		t.Errorf("keycloak disabled = %v", cm.disabled)
	}
	disabled, err := svc.GetIdentityClient(ctx, "acme", "org-acme-ci-bot")
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Status != types.IdentityClientStatusDisabled {
		t.Errorf("status = %q", disabled.Status)
	}

	// Unknown client 404s through the sentinel.
	if _, err := svc.GetIdentityClient(ctx, "acme", "org-acme-ghost"); !errors.Is(err, tenancy.ErrClientNotFound) {
		t.Errorf("err = %v, want ErrClientNotFound", err)
	}

	// Audit trail.
	events, err := audit.NewStore().List(ctx, database.Pool, org.ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"identity.client.created":        false,
		"identity.client.updated":        false,
		"identity.client.disabled":       false,
		"identity.client.secret_rotated": false,
	}
	for _, e := range events {
		if _, ok := want[e.Action]; ok {
			want[e.Action] = true
		}
	}
	for action, found := range want {
		if !found {
			t.Errorf("missing audit event %s", action)
		}
	}
}

func TestSetRBACMappings(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	svc := tenancy.NewService(database, newFakeIdP(), tenancy.NewStore(), audit.NewStore())
	org, teams, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	var devTeamID string
	for _, tm := range teams {
		if tm.Name == "developers" {
			devTeamID = tm.ID
		}
	}

	// Invalid role fails the whole request.
	if _, err := svc.SetRBACMappings(ctx, "user-1", "acme", []types.TeamRoleMapping{
		{Team: "developers", Role: "superuser"},
	}); err == nil {
		t.Error("expected error for invalid role")
	}

	// Unknown team fails the whole request with no partial writes.
	if _, err := svc.SetRBACMappings(ctx, "user-1", "acme", []types.TeamRoleMapping{
		{Team: "developers", Role: types.RoleViewer},
		{Team: "ghost", Role: types.RoleViewer},
	}); !errors.Is(err, tenancy.ErrTeamNotFound) {
		t.Errorf("err = %v, want ErrTeamNotFound", err)
	}
	after, err := svc.ListTeams(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tm := range after {
		if tm.Name == "developers" && tm.Role != types.RoleDeveloper {
			t.Errorf("developers role changed despite failed request: %q", tm.Role)
		}
	}

	// Valid bulk set applies atomically.
	changes, err := svc.SetRBACMappings(ctx, "user-1", "acme", []types.TeamRoleMapping{
		{Team: "developers", Role: types.RolePlatformEngineer},
		{Team: "viewers", Role: types.RoleOrgAdmin},
		{Team: "platform-team", Role: types.RolePlatformEngineer}, // unchanged
	})
	if err != nil {
		t.Fatalf("SetRBACMappings: %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("changes = %v, want 2 (unchanged team skipped)", changes)
	}
	after, _ = svc.ListTeams(ctx, org.ID)
	roles := map[string]types.Role{}
	for _, tm := range after {
		roles[tm.Name] = tm.Role
	}
	if roles["developers"] != types.RolePlatformEngineer || roles["viewers"] != types.RoleOrgAdmin {
		t.Errorf("roles = %v", roles)
	}

	// Audit + outbox, then tuple rewrite on dispatch.
	events, err := audit.NewStore().List(ctx, database.Pool, org.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "rbac.mappings.updated" {
			found = true
		}
	}
	if !found {
		t.Error("no rbac.mappings.updated audit event")
	}

	rec := &recordingStore{}
	disp := audit.NewDispatcher(database, 50*time.Millisecond, authz.NewTupleWriter(rec))
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	var delDev, addDev bool
	for _, tp := range rec.deleted {
		if tp.User == "team:"+devTeamID+"#member" && tp.Relation == "developer" {
			delDev = true
		}
	}
	for _, tp := range rec.written {
		if tp.User == "team:"+devTeamID+"#member" && tp.Relation == "platform_engineer" {
			addDev = true
		}
	}
	if !delDev || !addDev {
		t.Errorf("tuple rewrite missing: deleted=%v written=%v", rec.deleted, rec.written)
	}
}

// allowAdmin grants the org admin relation (fine PEP pass-through).
type allowAdmin struct{}

func (allowAdmin) Check(_ context.Context, _, relation, _ string) (bool, error) {
	return relation == authz.RelationAdmin, nil
}
func (allowAdmin) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func TestIdentityClientHTTPRoutes(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	cm := newFakeClientManager()
	svc := tenancy.NewService(database, newFakeIdP(), tenancy.NewStore(), audit.NewStore()).
		WithClientManager(cm)
	if _, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}

	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fixedValidator{id: &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}}, readyOK{})
	tenancy.NewHandler(svc, allowAdmin{}).
		WithScopesCatalog([]config.ServiceScopes{{Audience: "inari-server", Scopes: []string{"read"}}}).
		RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	do := func(method, path, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer good")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	// Create returns the secret once.
	resp := do(http.MethodPost, "/api/v1/tenants/acme/identity/clients",
		`{"name":"ci-bot","type":"service","audiences":["inari-server"],"scopes":["read"]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create: got %d", resp.StatusCode)
	}
	var created struct {
		Client types.IdentityClient `json:"client"`
		Secret string               `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Client.ClientID != "org-acme-ci-bot" || created.Secret != "secret-1" {
		t.Errorf("created = %+v", created)
	}

	// List / get.
	if resp := do(http.MethodGet, "/api/v1/tenants/acme/identity/clients", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("list: got %d", resp.StatusCode)
	}
	if resp := do(http.MethodGet, "/api/v1/tenants/acme/identity/clients/org-acme-ci-bot", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("get: got %d", resp.StatusCode)
	}
	if resp := do(http.MethodGet, "/api/v1/tenants/acme/identity/clients/org-acme-ghost", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("get unknown: got %d, want 404", resp.StatusCode)
	}

	// Patch.
	resp = do(http.MethodPatch, "/api/v1/tenants/acme/identity/clients/org-acme-ci-bot", `{"scopes":["read","write"]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch: got %d", resp.StatusCode)
	}

	// Put scopes.
	resp = do(http.MethodPut, "/api/v1/tenants/acme/identity/clients/org-acme-ci-bot/scopes", `{"scopes":["deploy"]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put scopes: got %d", resp.StatusCode)
	}
	var updated struct {
		Client types.IdentityClient `json:"client"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	if len(updated.Client.Scopes) != 1 || updated.Client.Scopes[0] != "deploy" {
		t.Errorf("scopes = %v", updated.Client.Scopes)
	}

	// Rotate returns the new secret once.
	resp = do(http.MethodPost, "/api/v1/tenants/acme/identity/clients/org-acme-ci-bot/secret:rotate", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate: got %d", resp.StatusCode)
	}
	var rotated struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Secret != "rotated-1" {
		t.Errorf("secret = %q", rotated.Secret)
	}

	// Scopes catalog.
	resp = do(http.MethodGet, "/api/v1/tenants/acme/identity/scopes", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scopes catalog: got %d", resp.StatusCode)
	}
	var catalog struct {
		Scopes []config.ServiceScopes `json:"scopes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Scopes) != 1 || catalog.Scopes[0].Audience != "inari-server" {
		t.Errorf("catalog = %+v", catalog)
	}

	// RBAC mappings.
	resp = do(http.MethodPut, "/api/v1/tenants/acme/rbac/mappings",
		`{"mappings":[{"team":"developers","role":"viewer"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mappings: got %d", resp.StatusCode)
	}
	resp = do(http.MethodPut, "/api/v1/tenants/acme/rbac/mappings",
		`{"mappings":[{"team":"ghost","role":"viewer"}]}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("mappings unknown team: got %d, want 404", resp.StatusCode)
	}
	resp = do(http.MethodPut, "/api/v1/tenants/acme/rbac/mappings",
		`{"mappings":[{"team":"developers","role":"superuser"}]}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("mappings bad role: got %d, want 400", resp.StatusCode)
	}

	// Delete disables.
	resp = do(http.MethodDelete, "/api/v1/tenants/acme/identity/clients/org-acme-ci-bot", "")
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: got %d", resp.StatusCode)
	}
	disabled, err := svc.GetIdentityClient(ctx, "acme", "org-acme-ci-bot")
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Status != types.IdentityClientStatusDisabled {
		t.Errorf("status = %q", disabled.Status)
	}
}
