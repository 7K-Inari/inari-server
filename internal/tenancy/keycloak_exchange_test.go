package tenancy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClusterDexClientSpecShape(t *testing.T) {
	spec := ClusterDexClientSpec("abc123", "https://dex.cluster.example", []string{"kubernetes"})
	if spec.ClientID != "cluster-abc123-dex" {
		t.Fatalf("clientID = %q", spec.ClientID)
	}
	if spec.ClientType != ClientTypeService {
		t.Fatalf("type = %q", spec.ClientType)
	}
	if !spec.StandardFlow {
		t.Fatal("standard flow must be enabled for Dex federation")
	}
	if !spec.GroupsClaim {
		t.Fatal("groups claim required for Dex RBAC passthrough")
	}
	if spec.TokenExchange {
		t.Fatal("dex client must not get token-exchange permission")
	}
	if len(spec.RedirectURIs) != 1 || spec.RedirectURIs[0] != "https://dex.cluster.example/callback" {
		t.Fatalf("redirects = %v", spec.RedirectURIs)
	}
	if len(spec.Audiences) != 1 || spec.Audiences[0] != "kubernetes" {
		t.Fatalf("audiences = %v", spec.Audiences)
	}
}

func TestCreateClusterDexClient(t *testing.T) {
	srv, f := newClientCrudFake(t)
	k := NewKeycloakAdmin(srv.URL, "inari", "admin", "secret")
	id, secret, err := k.CreateClusterDexClient(context.Background(), "abc123", "https://dex.cluster.example", []string{"kubernetes"})
	if err != nil {
		t.Fatal(err)
	}
	if id != "cluster-abc123-dex" {
		t.Fatalf("id = %q", id)
	}
	if secret != "initial-secret" {
		t.Fatalf("secret = %q", secret)
	}
	if f.created["standardFlowEnabled"] != true {
		t.Errorf("standardFlowEnabled = %v", f.created["standardFlowEnabled"])
	}
	if f.created["serviceAccountsEnabled"] != true {
		t.Errorf("serviceAccountsEnabled = %v", f.created["serviceAccountsEnabled"])
	}
	attrs, _ := f.created["attributes"].(map[string]any)
	if attrs["standard.token.exchange.enabled"] != nil {
		t.Errorf("dex client must not enable token exchange: %v", attrs)
	}
	mappers, _ := f.created["protocolMappers"].([]any)
	var aud, groups int
	for _, m := range mappers {
		mm, _ := m.(map[string]any)
		switch mm["protocolMapper"] {
		case "oidc-audience-mapper":
			aud++
		case "oidc-group-membership-mapper":
			groups++
		}
	}
	if aud != 1 || groups != 1 {
		t.Errorf("mappers: audience=%d groups=%d", aud, groups)
	}
}

func TestCreateTokenExchangeClient(t *testing.T) {
	srv, f := newClientCrudFake(t)
	k := NewKeycloakAdmin(srv.URL, "inari", "admin", "secret")
	spec := ClientSpec{
		ClientID:      "ext-argocd",
		Name:          "extension-argocd",
		ClientType:    ClientTypeService,
		Audiences:     []string{"inari-extension-gateway", "argocd-server"},
		Enabled:       true,
		TokenExchange: true,
	}
	if _, err := k.CreateClient(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	attrs, _ := f.created["attributes"].(map[string]any)
	if attrs["standard.token.exchange.enabled"] != "true" {
		t.Fatalf("token exchange attribute missing: %v", attrs)
	}
	mappers, _ := f.created["protocolMappers"].([]any)
	var auds []string
	for _, m := range mappers {
		mm, _ := m.(map[string]any)
		if mm["protocolMapper"] == "oidc-audience-mapper" {
			cfg, _ := mm["config"].(map[string]any)
			auds = append(auds, cfg["included.client.audience"].(string))
		}
	}
	if len(auds) != 2 || auds[0] != "inari-extension-gateway" || auds[1] != "argocd-server" {
		t.Fatalf("audience mappers = %v (least privilege: exactly the declared set)", auds)
	}
}

func TestClientSecretReadsAnyClient(t *testing.T) {
	srv, _ := newClientCrudFake(t)
	k := NewKeycloakAdmin(srv.URL, "inari", "admin", "secret")
	secret, err := k.ClientSecret(context.Background(), "ext-argocd")
	if err != nil {
		t.Fatal(err)
	}
	if secret != "initial-secret" {
		t.Fatalf("secret = %q", secret)
	}
}

func TestClusterDexConflictIsIdempotent(t *testing.T) {
	// newClientCrudFake always returns 201; drive a 409-only fake to assert
	// CreateClient tolerates conflicts and still reads the secret.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/realms/inari/protocol/openid-connect/token":
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		case r.URL.Path == "/admin/realms/inari/clients" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusConflict)
		case r.URL.Path == "/admin/realms/inari/clients" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[{"id":"uuid-9"}]`))
		case r.URL.Path == "/admin/realms/inari/clients/uuid-9/client-secret":
			_, _ = w.Write([]byte(`{"value":"existing-secret"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	k := NewKeycloakAdmin(srv.URL, "inari", "admin", "secret")
	id, secret, err := k.CreateClusterDexClient(context.Background(), "abc123", "https://dex.cluster.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if id != "cluster-abc123-dex" || secret != "existing-secret" {
		t.Fatalf("id=%q secret=%q", id, secret)
	}
}
