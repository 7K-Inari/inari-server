package tenancy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// idpCrudFake fakes the Keycloak Admin endpoints used by IdP brokering:
// instance CRUD, org link/unlink, mapper sync, org domains, and the group
// creation the hardcoded group mapper depends on.
type idpCrudFake struct {
	mu           sync.Mutex
	createdIdP   map[string]any
	updatedIdP   map[string]any
	idpDeleted   bool
	linked       []string // raw link bodies (JSON string of the alias)
	linkStatus   int
	unlinked     []string
	createdMaps  []map[string]any
	deletedMaps  []string
	orgDomains   []string
	groups       []string
	existingMaps []map[string]any
}

func newIdpCrudFake(t *testing.T) (*httptest.Server, *idpCrudFake) {
	t.Helper()
	f := &idpCrudFake{linkStatus: http.StatusCreated}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		base := "/admin/realms/inari"
		switch {
		case r.URL.Path == "/realms/inari/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))

		// Group creation (tenant-<slug> then members child).
		case r.URL.Path == base+"/groups" && r.Method == http.MethodPost:
			var body struct{ Name string }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode group body: %v", err)
			}
			f.groups = append(f.groups, body.Name)
			w.Header().Set("Location", "http://kc"+base+"/groups/gid-"+body.Name)
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == base+"/groups/gid-tenant-acme/children" && r.Method == http.MethodPost:
			var body struct{ Name string }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode child group body: %v", err)
			}
			f.groups = append(f.groups, "tenant-acme/"+body.Name)
			w.Header().Set("Location", "http://kc"+base+"/groups/gid-members")
			w.WriteHeader(http.StatusCreated)

		// IdP instance CRUD.
		case r.URL.Path == base+"/identity-provider/instances" && r.Method == http.MethodPost:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode idp create body: %v", err)
			}
			f.createdIdP = body
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == base+"/identity-provider/instances/org-acme-sso" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"alias":      "org-acme-sso",
				"providerId": "oidc",
				"config": map[string]any{
					"clientId":             "old-client",
					"clientSecret":         idpMaskedSecret,
					"issuer":               "https://old.example.com",
					"useDiscoveryEndpoint": "true",
				},
			})
		case r.URL.Path == base+"/identity-provider/instances/org-acme-sso" && r.Method == http.MethodPut:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode idp update body: %v", err)
			}
			f.updatedIdP = body
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == base+"/identity-provider/instances/org-acme-sso" && r.Method == http.MethodDelete:
			f.idpDeleted = true
			w.WriteHeader(http.StatusNoContent)

		// Mappers.
		case r.URL.Path == base+"/identity-provider/instances/org-acme-sso/mappers" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(f.existingMaps)
		case r.URL.Path == base+"/identity-provider/instances/org-acme-sso/mappers" && r.Method == http.MethodPost:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode mapper body: %v", err)
			}
			f.createdMaps = append(f.createdMaps, body)
			w.Header().Set("Location", "http://kc"+base+"/identity-provider/instances/org-acme-sso/mappers/m-1")
			w.WriteHeader(http.StatusCreated)
		case strings.HasPrefix(r.URL.Path, base+"/identity-provider/instances/org-acme-sso/mappers/") && r.Method == http.MethodDelete:
			f.deletedMaps = append(f.deletedMaps, strings.TrimPrefix(r.URL.Path, base+"/identity-provider/instances/org-acme-sso/mappers/"))
			w.WriteHeader(http.StatusNoContent)

		// Org link/unlink.
		case r.URL.Path == base+"/organizations/org-1/identity-providers" && r.Method == http.MethodPost:
			var alias string
			if err := json.NewDecoder(r.Body).Decode(&alias); err != nil {
				t.Errorf("link body is not a plain JSON string: %v", err)
			}
			f.linked = append(f.linked, alias)
			w.WriteHeader(f.linkStatus)
		case r.URL.Path == base+"/organizations/org-1/identity-providers/org-acme-sso" && r.Method == http.MethodDelete:
			f.unlinked = append(f.unlinked, "org-acme-sso")
			w.WriteHeader(http.StatusNoContent)

		// Org read-modify-write for domains.
		case r.URL.Path == base+"/organizations/org-1" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "org-1", "name": "acme", "alias": "acme",
				"domains": []map[string]any{{"name": "acme.inari.local", "verified": false}},
			})
		case r.URL.Path == base+"/organizations/org-1" && r.Method == http.MethodPut:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode org update body: %v", err)
			}
			for _, d := range body["domains"].([]any) {
				f.orgDomains = append(f.orgDomains, d.(map[string]any)["name"].(string))
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv, f
}

func testBrokerSpec() BrokerIdPSpec {
	return BrokerIdPSpec{
		Alias:        "org-acme-sso",
		IssuerURL:    "https://idp.example.com",
		ClientID:     "inari-acme",
		ClientSecret: "super-secret",
		EmailClaim:   "mail",
		GroupsClaim:  "groups",
		OrgGroupPath: "tenant-acme/members",
	}
}

func TestCreateIdP(t *testing.T) {
	srv, f := newIdpCrudFake(t)
	defer srv.Close()
	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")

	if err := k.CreateIdP(context.Background(), testBrokerSpec()); err != nil {
		t.Fatalf("CreateIdP: %v", err)
	}
	if f.createdIdP["providerId"] != "oidc" || f.createdIdP["alias"] != "org-acme-sso" {
		t.Errorf("idp rep = %v", f.createdIdP)
	}
	if f.createdIdP["trustEmail"] != true || f.createdIdP["hideOnLogin"] != true {
		t.Errorf("trust/hide flags wrong: %v", f.createdIdP)
	}
	cfg, _ := f.createdIdP["config"].(map[string]any)
	if cfg["clientId"] != "inari-acme" || cfg["clientSecret"] != "super-secret" ||
		cfg["issuer"] != "https://idp.example.com" || cfg["useDiscoveryEndpoint"] != "true" {
		t.Errorf("config = %v", cfg)
	}
	if cfg["kc.org.broker.redirect.mode.email-matches"] != "true" {
		t.Errorf("email-matches redirect mode not set: %v", cfg)
	}
	// The hardcoded mapper's target group is ensured first.
	if len(f.groups) != 2 || f.groups[1] != "tenant-acme/members" {
		t.Errorf("groups created = %v", f.groups)
	}
	// Mappers: hardcoded org-members group + advanced claim-to-group + email
	// attribute importer, all broker- owned.
	var names []string
	for _, m := range f.createdMaps {
		names = append(names, m["name"].(string))
	}
	if len(names) != 3 || names[0] != "broker-org-members" || names[1] != "broker-groups-groups" || names[2] != "broker-email" {
		t.Errorf("mappers = %v", names)
	}
}

func TestUpdateIdPEchoesMaskedSecret(t *testing.T) {
	srv, f := newIdpCrudFake(t)
	defer srv.Close()
	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")

	spec := testBrokerSpec()
	spec.ClientSecret = "" // keep the existing secret
	if err := k.UpdateIdP(context.Background(), spec); err != nil {
		t.Fatalf("UpdateIdP: %v", err)
	}
	cfg, _ := f.updatedIdP["config"].(map[string]any)
	if cfg["clientSecret"] != idpMaskedSecret {
		t.Errorf("masked secret not echoed back: %v", cfg["clientSecret"])
	}
	if cfg["clientId"] != "inari-acme" || cfg["issuer"] != "https://idp.example.com" {
		t.Errorf("config = %v", cfg)
	}
}

func TestUpdateIdPRotatesSecret(t *testing.T) {
	srv, f := newIdpCrudFake(t)
	defer srv.Close()
	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")

	spec := testBrokerSpec()
	spec.ClientSecret = "new-secret"
	if err := k.UpdateIdP(context.Background(), spec); err != nil {
		t.Fatalf("UpdateIdP: %v", err)
	}
	cfg, _ := f.updatedIdP["config"].(map[string]any)
	if cfg["clientSecret"] != "new-secret" {
		t.Errorf("clientSecret = %v, want new-secret", cfg["clientSecret"])
	}
}

func TestSyncIdPMappersReplacesOnlyOwned(t *testing.T) {
	srv, f := newIdpCrudFake(t)
	defer srv.Close()
	f.existingMaps = []map[string]any{
		{"id": "m-old", "name": "broker-groups-old"},
		{"id": "m-other", "name": "someone-elses-mapper"},
	}
	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")

	spec := testBrokerSpec()
	spec.ClientSecret = ""
	if err := k.UpdateIdP(context.Background(), spec); err != nil {
		t.Fatalf("UpdateIdP: %v", err)
	}
	if len(f.deletedMaps) != 1 || f.deletedMaps[0] != "m-old" {
		t.Errorf("deleted mappers = %v, want only broker- owned", f.deletedMaps)
	}
}

func TestLinkIdPToOrgConflictIsIdempotent(t *testing.T) {
	srv, f := newIdpCrudFake(t)
	defer srv.Close()
	f.linkStatus = http.StatusConflict
	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")

	if err := k.LinkIdPToOrg(context.Background(), "org-1", "org-acme-sso"); err != nil {
		t.Fatalf("LinkIdPToOrg (409): %v", err)
	}
	if len(f.linked) != 1 || f.linked[0] != "org-acme-sso" {
		t.Errorf("linked = %v", f.linked)
	}
}

func TestDeleteIdPUnlinksFirst(t *testing.T) {
	srv, f := newIdpCrudFake(t)
	defer srv.Close()
	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")

	if err := k.UnlinkIdPFromOrg(context.Background(), "org-1", "org-acme-sso"); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	if err := k.DeleteIdP(context.Background(), "org-acme-sso"); err != nil {
		t.Fatalf("DeleteIdP: %v", err)
	}
	if len(f.unlinked) != 1 || !f.idpDeleted {
		t.Errorf("unlinked=%v deleted=%v", f.unlinked, f.idpDeleted)
	}
}

func TestSetOrgDomainsKeepsPlaceholder(t *testing.T) {
	srv, f := newIdpCrudFake(t)
	defer srv.Close()
	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")

	err := k.SetOrgDomains(context.Background(), "org-1",
		[]string{"acme.inari.local", "acme.com", "*.subs.acme.com"})
	if err != nil {
		t.Fatalf("SetOrgDomains: %v", err)
	}
	if len(f.orgDomains) != 3 || f.orgDomains[0] != "acme.inari.local" {
		t.Errorf("domains = %v", f.orgDomains)
	}
}
