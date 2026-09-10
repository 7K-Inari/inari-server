package tenancy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// clientCrudFake fakes the Keycloak Admin endpoints used by the generic
// client CRUD: create/find/secret/client-scopes/optional-scope-links/update/
// rotate. It records requests for assertions.
type clientCrudFake struct {
	mu             sync.Mutex
	created        map[string]any
	updated        map[string]any
	optionalScopes []string
	realmScopes    map[string]string // name -> id
	secretCalls    int
	rotatedSecret  string
}

func newClientCrudFake(t *testing.T) (*httptest.Server, *clientCrudFake) {
	t.Helper()
	f := &clientCrudFake{
		realmScopes:   map[string]string{"read": "scope-read"},
		rotatedSecret: "rotated-secret",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/realms/inari/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		case r.URL.Path == "/admin/realms/inari/clients" && r.Method == http.MethodPost:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode create body: %v", err)
			}
			f.created = body
			w.Header().Set("Location", "http://kc/admin/realms/inari/clients/uuid-1")
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == "/admin/realms/inari/clients" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[{"id":"uuid-1"}]`))
		case r.URL.Path == "/admin/realms/inari/clients/uuid-1" && r.Method == http.MethodGet:
			rep := map[string]any{
				"id":                        "uuid-1",
				"clientId":                  "org-acme-foo",
				"enabled":                   true,
				"publicClient":              false,
				"serviceAccountsEnabled":    true,
				"optionalClientScopes":      []string{"read"},
				"redirectUris":              []string{},
				"standardFlowEnabled":       false,
				"directAccessGrantsEnabled": false,
				"protocolMappers": []map[string]any{{
					"name":           "audience-inari-server",
					"protocol":       "openid-connect",
					"protocolMapper": "oidc-audience-mapper",
					"config":         map[string]string{"included.client.audience": "inari-server"},
				}},
			}
			_ = json.NewEncoder(w).Encode(rep)
		case r.URL.Path == "/admin/realms/inari/clients/uuid-1" && r.Method == http.MethodPut:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode update body: %v", err)
			}
			f.updated = body
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/admin/realms/inari/clients/uuid-1/client-secret" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"type":"secret","value":"initial-secret"}`))
		case r.URL.Path == "/admin/realms/inari/clients/uuid-1/client-secret" && r.Method == http.MethodPost:
			f.secretCalls++
			_, _ = w.Write([]byte(fmt.Sprintf(`{"type":"secret","value":%q}`, f.rotatedSecret)))
		case r.URL.Path == "/admin/realms/inari/client-scopes" && r.Method == http.MethodGet:
			type scopeRep struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			var reps []scopeRep
			for name, id := range f.realmScopes {
				reps = append(reps, scopeRep{ID: id, Name: name})
			}
			_ = json.NewEncoder(w).Encode(reps)
		case r.URL.Path == "/admin/realms/inari/client-scopes" && r.Method == http.MethodPost:
			var body struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode client-scope body: %v", err)
			}
			if _, ok := f.realmScopes[body.Name]; ok {
				w.WriteHeader(http.StatusConflict)
				return
			}
			id := "scope-" + body.Name
			f.realmScopes[body.Name] = id
			w.Header().Set("Location", "http://kc/admin/realms/inari/client-scopes/"+id)
			w.WriteHeader(http.StatusCreated)
		case strings.HasPrefix(r.URL.Path, "/admin/realms/inari/clients/uuid-1/optional-client-scopes/"):
			f.optionalScopes = append(f.optionalScopes, strings.TrimPrefix(r.URL.Path, "/admin/realms/inari/clients/uuid-1/optional-client-scopes/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv, f
}

func TestCreateServiceClient(t *testing.T) {
	srv, f := newClientCrudFake(t)
	defer srv.Close()

	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")
	secret, err := k.CreateClient(context.Background(), ClientSpec{
		ClientID:   "org-acme-foo",
		Name:       "foo",
		ClientType: ClientTypeService,
		Audiences:  []string{"inari-server", "inari-agent-gateway"},
		Scopes:     []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if secret != "initial-secret" {
		t.Errorf("secret = %q, want initial-secret", secret)
	}
	if f.created["clientId"] != "org-acme-foo" {
		t.Errorf("clientId = %v", f.created["clientId"])
	}
	if f.created["publicClient"] != false || f.created["serviceAccountsEnabled"] != true {
		t.Errorf("service client flags wrong: %v", f.created)
	}
	if f.created["standardFlowEnabled"] != false {
		t.Errorf("standardFlowEnabled = %v", f.created["standardFlowEnabled"])
	}
	mappers, _ := f.created["protocolMappers"].([]any)
	var auds []string
	for _, m := range mappers {
		mm, _ := m.(map[string]any)
		if mm["protocolMapper"] == "oidc-audience-mapper" {
			cfg, _ := mm["config"].(map[string]any)
			auds = append(auds, fmt.Sprint(cfg["included.client.audience"]))
		}
	}
	if len(auds) != 2 {
		t.Errorf("audience mappers = %v, want 2", auds)
	}
	// Both scopes linked as optional client scopes; "write" created on demand.
	if len(f.optionalScopes) != 2 {
		t.Errorf("optional scope links = %v, want 2", f.optionalScopes)
	}
	if f.realmScopes["write"] == "" {
		t.Errorf("realm client scope 'write' not created: %v", f.realmScopes)
	}
}

func TestCreatePublicClientHasNoSecret(t *testing.T) {
	srv, f := newClientCrudFake(t)
	defer srv.Close()

	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")
	secret, err := k.CreateClient(context.Background(), ClientSpec{
		ClientID:     "org-acme-web",
		Name:         "web",
		ClientType:   ClientTypePublic,
		Audiences:    []string{"inari-server"},
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if secret != "" {
		t.Errorf("public client must not return a secret, got %q", secret)
	}
	if f.created["publicClient"] != true || f.created["standardFlowEnabled"] != true {
		t.Errorf("public client flags wrong: %v", f.created)
	}
	uris, _ := f.created["redirectUris"].([]any)
	if len(uris) != 1 || uris[0] != "https://app.example.com/callback" {
		t.Errorf("redirectUris = %v", uris)
	}
}

func TestRotateClientSecret(t *testing.T) {
	srv, f := newClientCrudFake(t)
	defer srv.Close()

	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")
	secret, err := k.RotateClientSecret(context.Background(), "org-acme-foo")
	if err != nil {
		t.Fatalf("RotateClientSecret: %v", err)
	}
	if secret != "rotated-secret" {
		t.Errorf("secret = %q, want rotated-secret", secret)
	}
	if f.secretCalls != 1 {
		t.Errorf("secretCalls = %d, want 1", f.secretCalls)
	}
}

func TestUpdateClientSyncsScopesAndURIs(t *testing.T) {
	srv, f := newClientCrudFake(t)
	defer srv.Close()

	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")
	err := k.UpdateClient(context.Background(), ClientSpec{
		ClientID:     "org-acme-foo",
		Name:         "foo-renamed",
		ClientType:   ClientTypeService,
		Audiences:    []string{"inari-server"},
		Scopes:       []string{"read", "deploy"},
		RedirectURIs: []string{},
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if f.updated["name"] != "foo-renamed" {
		t.Errorf("name = %v", f.updated["name"])
	}
	// deploy scope was created and both scopes linked.
	if f.realmScopes["deploy"] == "" {
		t.Errorf("realm client scope 'deploy' not created: %v", f.realmScopes)
	}
	if len(f.optionalScopes) != 2 {
		t.Errorf("optional scope links = %v, want 2", f.optionalScopes)
	}
}

func TestGetClient(t *testing.T) {
	srv, _ := newClientCrudFake(t)
	defer srv.Close()

	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")
	spec, err := k.GetClient(context.Background(), "org-acme-foo")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if spec == nil {
		t.Fatal("spec = nil")
	}
	if spec.ClientID != "org-acme-foo" || spec.ClientType != ClientTypeService {
		t.Errorf("spec = %+v", spec)
	}
	if len(spec.Audiences) != 1 || spec.Audiences[0] != "inari-server" {
		t.Errorf("audiences = %v", spec.Audiences)
	}
	if len(spec.Scopes) != 1 || spec.Scopes[0] != "read" {
		t.Errorf("scopes = %v", spec.Scopes)
	}
}
