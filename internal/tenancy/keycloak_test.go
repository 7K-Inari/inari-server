package tenancy

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestListGroupMembers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/inari/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		case "/admin/realms/inari/groups":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":"g1","name":"platform-admins"}]`))
		case "/admin/realms/inari/groups/g1/members":
			if got := r.URL.Query().Get("max"); got != "500" {
				t.Errorf("max = %q, want 500", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":"u1"},{"id":"u2"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")
	members, err := k.ListGroupMembers(context.Background(), "platform-admins")
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(members) != 2 || members[0] != "u1" || members[1] != "u2" {
		t.Errorf("members = %v, want [u1 u2]", members)
	}
}

func TestListGroupMembersPaginates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/inari/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		case "/admin/realms/inari/groups":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":"g1","name":"platform-admins"}]`))
		case "/admin/realms/inari/groups/g1/members":
			first := r.URL.Query().Get("first")
			w.Header().Set("Content-Type", "application/json")
			switch first {
			case "0":
				// Full page: exactly pageSize users, so the client must ask again.
				users := make([]map[string]string, 500)
				for i := range users {
					users[i] = map[string]string{"id": fmt.Sprintf("u%d", i)}
				}
				_ = json.NewEncoder(w).Encode(users)
			case "500":
				_, _ = w.Write([]byte(`[{"id":"u500"}]`))
			default:
				t.Errorf("unexpected page first=%s", first)
				w.WriteHeader(http.StatusBadRequest)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")
	members, err := k.ListGroupMembers(context.Background(), "platform-admins")
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(members) != 501 || members[0] != "u0" || members[500] != "u500" {
		t.Errorf("members = %d entries, want 501 across two pages", len(members))
	}
}

func TestClusterClientSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/realms/inari/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		case r.URL.Path == "/admin/realms/inari/clients" && r.Method == http.MethodGet:
			if got := r.URL.Query().Get("clientId"); got != "cluster-abc" {
				t.Errorf("clientId query = %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":"uuid-1"}]`))
		case r.URL.Path == "/admin/realms/inari/clients/uuid-1/client-secret":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"type":"secret","value":"s3cr3t"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")
	secret, err := k.ClusterClientSecret(context.Background(), "cluster-abc")
	if err != nil {
		t.Fatal(err)
	}
	if secret != "s3cr3t" {
		t.Errorf("secret = %q", secret)
	}
}

func TestClusterClientSecretMissingClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/inari/protocol/openid-connect/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	k := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")
	if _, err := k.ClusterClientSecret(context.Background(), "cluster-gone"); err == nil {
		t.Fatal("expected error for missing client")
	}
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
