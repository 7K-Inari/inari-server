package tenancy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// keycloakTestServer fakes the token endpoint and captures POST bodies.
func keycloakTestServer(t *testing.T, bodies *map[string][]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/inari/protocol/openid-connect/token" {
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "client_credentials" {
				t.Errorf("grant_type = %q, want client_credentials", got)
			}
			if r.Form.Get("client_id") == "" || r.Form.Get("client_secret") == "" {
				t.Errorf("token request missing client_id/client_secret: %v", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/admin/realms/inari/clients" {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode client create body: %v", err)
			}
			raw, _ := json.Marshal(body)
			(*bodies)["createClient"] = raw
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestCreateClusterClientIncludesAudienceMapper(t *testing.T) {
	bodies := map[string][]byte{}
	srv := keycloakTestServer(t, &bodies)
	defer srv.Close()

	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")
	clientID, err := k.CreateClusterClient(context.Background(), "abc-123")
	if err != nil {
		t.Fatal(err)
	}
	if clientID != "cluster-abc-123" {
		t.Errorf("clientID = %q, want cluster-abc-123", clientID)
	}

	var body struct {
		ClientID        string `json:"clientId"`
		ProtocolMappers []struct {
			Name           string            `json:"name"`
			Protocol       string            `json:"protocol"`
			ProtocolMapper string            `json:"protocolMapper"`
			Config         map[string]string `json:"config"`
		} `json:"protocolMappers"`
	}
	if err := json.Unmarshal(bodies["createClient"], &body); err != nil {
		t.Fatalf("no create body captured: %v", err)
	}
	if body.ClientID != "cluster-abc-123" {
		t.Errorf("clientId = %q", body.ClientID)
	}

	var aud map[string]string
	found := false
	for _, m := range body.ProtocolMappers {
		if m.ProtocolMapper == "oidc-audience-mapper" {
			aud = m.Config
			found = true
		}
	}
	if !found {
		t.Fatalf("no oidc-audience-mapper in protocolMappers: %s", bodies["createClient"])
	}
	if got := aud["included.client.audience"]; got != "inari-server" {
		t.Errorf("included.client.audience = %q, want inari-server", got)
	}
	if aud["access.token.claim"] != "true" {
		t.Errorf("access.token.claim = %q", aud["access.token.claim"])
	}
	if aud["id.token.claim"] != "false" {
		t.Errorf("id.token.claim = %q", aud["id.token.claim"])
	}
}
