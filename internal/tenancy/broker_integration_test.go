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

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeBrokerManager fakes the Keycloak IdP brokering CRUD.
type fakeBrokerManager struct {
	mu      sync.Mutex
	idps    map[string]*tenancy.BrokerIdPSpec // keyed by full KC alias
	linked  map[string]string                 // kcOrgID -> alias
	domains map[string][]string               // kcOrgID -> domains
	order   []string
}

func newFakeBrokerManager() *fakeBrokerManager {
	return &fakeBrokerManager{
		idps:    map[string]*tenancy.BrokerIdPSpec{},
		linked:  map[string]string{},
		domains: map[string][]string{},
	}
}

func (f *fakeBrokerManager) CreateIdP(_ context.Context, spec tenancy.BrokerIdPSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.idps[spec.Alias]; ok {
		return fmt.Errorf("idp %s exists", spec.Alias)
	}
	cp := spec
	f.idps[spec.Alias] = &cp
	f.order = append(f.order, "create:"+spec.Alias)
	return nil
}

func (f *fakeBrokerManager) UpdateIdP(_ context.Context, spec tenancy.BrokerIdPSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.idps[spec.Alias]; !ok {
		return fmt.Errorf("idp %s not found", spec.Alias)
	}
	// Secret is write-only: an empty spec secret preserves the stored one.
	if spec.ClientSecret == "" {
		spec.ClientSecret = f.idps[spec.Alias].ClientSecret
	}
	cp := spec
	f.idps[spec.Alias] = &cp
	return nil
}

func (f *fakeBrokerManager) DeleteIdP(_ context.Context, alias string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.idps, alias)
	f.order = append(f.order, "delete:"+alias)
	return nil
}

func (f *fakeBrokerManager) LinkIdPToOrg(_ context.Context, kcOrgID, alias string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.linked[kcOrgID] = alias
	f.order = append(f.order, "link:"+alias)
	return nil
}

func (f *fakeBrokerManager) UnlinkIdPFromOrg(_ context.Context, kcOrgID, alias string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.linked, kcOrgID)
	f.order = append(f.order, "unlink:"+alias)
	return nil
}

func (f *fakeBrokerManager) SetOrgDomains(_ context.Context, kcOrgID string, domains []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains[kcOrgID] = domains
	return nil
}

func TestBrokeredIdPLifecycle(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	bm := newFakeBrokerManager()
	svc := tenancy.NewService(database, newFakeIdP(), tenancy.NewStore(), audit.NewStore()).
		WithIdentityProviderManager(bm)
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}

	broker, err := svc.CreateBrokeredIdP(ctx, "user-1", "acme", &types.BrokeredIdP{
		Alias:       "sso",
		IssuerURL:   "https://idp.example.com",
		ClientID:    "inari-acme",
		DomainHints: []string{"acme.com"},
		ClaimMapping: types.IdPClaimMapping{
			Email:  "mail",
			Groups: "groups",
		},
	}, "super-secret")
	if err != nil {
		t.Fatalf("CreateBrokeredIdP: %v", err)
	}
	if bm.idps["org-acme-sso"] == nil {
		t.Fatal("keycloak idp not created")
	}
	if bm.idps["org-acme-sso"].ClientSecret != "super-secret" {
		t.Error("secret not forwarded to keycloak")
	}
	if bm.idps["org-acme-sso"].OrgGroupPath != "tenant-acme/members" {
		t.Errorf("org group path = %q", bm.idps["org-acme-sso"].OrgGroupPath)
	}
	if bm.linked[org.KeycloakOrgID] != "org-acme-sso" {
		t.Errorf("linked = %v", bm.linked)
	}
	if got := bm.domains[org.KeycloakOrgID]; len(got) != 2 || got[0] != "acme.inari.local" || got[1] != "acme.com" {
		t.Errorf("domains = %v", got)
	}

	// One IdP per org in v1.
	if _, err := svc.CreateBrokeredIdP(ctx, "user-1", "acme", &types.BrokeredIdP{
		Alias: "other", IssuerURL: "https://other.example.com", ClientID: "c",
	}, "s"); !errors.Is(err, tenancy.ErrBrokerExists) {
		t.Errorf("second idp err = %v, want ErrBrokerExists", err)
	}

	// Update keeps the secret when none is supplied.
	broker.ClientID = "inari-acme-2"
	if err := svc.UpdateBrokeredIdP(ctx, "user-1", "acme", broker, ""); err != nil {
		t.Fatalf("UpdateBrokeredIdP: %v", err)
	}
	if bm.idps["org-acme-sso"].ClientSecret != "super-secret" {
		t.Error("secret lost on secret-less update")
	}
	if bm.idps["org-acme-sso"].ClientID != "inari-acme-2" {
		t.Errorf("clientID = %q", bm.idps["org-acme-sso"].ClientID)
	}
	reloaded, err := svc.GetBrokeredIdP(ctx, "acme", "sso")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ClientID != "inari-acme-2" || reloaded.ClaimMapping.Groups != "groups" {
		t.Errorf("reloaded = %+v", reloaded)
	}

	// Unknown alias 404s through the sentinel.
	if _, err := svc.GetBrokeredIdP(ctx, "acme", "ghost"); !errors.Is(err, tenancy.ErrBrokerNotFound) {
		t.Errorf("err = %v, want ErrBrokerNotFound", err)
	}

	// Delete unlinks before deleting the instance.
	if err := svc.DeleteBrokeredIdP(ctx, "user-1", "acme", "sso"); err != nil {
		t.Fatalf("DeleteBrokeredIdP: %v", err)
	}
	unlinkIdx, deleteIdx := -1, -1
	for i, op := range bm.order {
		if op == "unlink:org-acme-sso" {
			unlinkIdx = i
		}
		if op == "delete:org-acme-sso" {
			deleteIdx = i
		}
	}
	if unlinkIdx == -1 || deleteIdx == -1 || unlinkIdx > deleteIdx {
		t.Errorf("unlink must precede delete: order=%v", bm.order)
	}
	if _, err := svc.GetBrokeredIdP(ctx, "acme", "sso"); !errors.Is(err, tenancy.ErrBrokerNotFound) {
		t.Errorf("post-delete err = %v, want ErrBrokerNotFound", err)
	}

	// Audit trail.
	events, err := audit.NewStore().List(ctx, database.Pool, org.ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"idp.broker.created": false,
		"idp.broker.updated": false,
		"idp.broker.deleted": false,
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

func TestBrokeredIdPHTTPRoutes(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	bm := newFakeBrokerManager()
	svc := tenancy.NewService(database, newFakeIdP(), tenancy.NewStore(), audit.NewStore()).
		WithIdentityProviderManager(bm)
	if _, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}

	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fixedValidator{id: &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}}, readyOK{})
	tenancy.NewHandler(svc, allowAdmin{}).RegisterRoutes(api)
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

	// Create; the response must never carry the secret.
	resp := do(http.MethodPost, "/api/v1/tenants/acme/identity/providers",
		`{"alias":"sso","issuerUrl":"https://idp.example.com","clientId":"inari-acme","clientSecret":"super-secret","claimMapping":{"email":"mail","groups":"groups"},"domainHints":["acme.com"]}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d: %s", resp.StatusCode, b)
	}
	raw, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(raw), "super-secret") {
		t.Fatalf("secret leaked in response: %s", raw)
	}

	// Second create conflicts (one IdP per org).
	resp = do(http.MethodPost, "/api/v1/tenants/acme/identity/providers",
		`{"alias":"other","issuerUrl":"https://other.example.com","clientId":"c","clientSecret":"s"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("second create: got %d, want 409", resp.StatusCode)
	}

	// Invalid domain hint is a clean 400.
	resp = do(http.MethodPost, "/api/v1/tenants/acme/identity/providers",
		`{"alias":"x","issuerUrl":"https://x.example.com","clientId":"c","clientSecret":"s","domainHints":["BAD DOMAIN"]}`)
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("invalid domain: got %d, want 400", resp.StatusCode)
	}

	// List / get.
	if resp := do(http.MethodGet, "/api/v1/tenants/acme/identity/providers", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("list: got %d", resp.StatusCode)
	}
	resp = do(http.MethodGet, "/api/v1/tenants/acme/identity/providers/sso", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get: got %d", resp.StatusCode)
	}
	var got struct {
		Provider types.BrokeredIdP `json:"provider"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Provider.Alias != "sso" || got.Provider.ClaimMapping.Groups != "groups" {
		t.Errorf("provider = %+v", got.Provider)
	}
	if resp := do(http.MethodGet, "/api/v1/tenants/acme/identity/providers/ghost", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("get unknown: got %d, want 404", resp.StatusCode)
	}

	// Patch rotates the secret when set.
	resp = do(http.MethodPatch, "/api/v1/tenants/acme/identity/providers/sso", `{"clientId":"inari-acme-2","clientSecret":"rotated"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch: got %d", resp.StatusCode)
	}
	if bm.idps["org-acme-sso"].ClientSecret != "rotated" {
		t.Error("secret not rotated")
	}

	// Delete.
	resp = do(http.MethodDelete, "/api/v1/tenants/acme/identity/providers/sso", "")
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: got %d", resp.StatusCode)
	}
	if resp := do(http.MethodDelete, "/api/v1/tenants/acme/identity/providers/sso", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("re-delete: got %d, want 404", resp.StatusCode)
	}
}
