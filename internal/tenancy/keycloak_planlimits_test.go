package tenancy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnsureOrganizationResolvesCreateConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/inari/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accessToken":"ignored","access_token":"tok","expires_in":300}`))
		case "/admin/realms/inari/organizations":
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusConflict)
				return
			}
			if got := r.URL.Query().Get("search"); got != "acme" {
				t.Fatalf("search = %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":"kc-other","alias":"other"},{"id":"kc-acme","alias":"acme"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	admin := NewKeycloakAdmin(srv.URL, "inari", "client", "secret")
	id, err := admin.EnsureOrganization(context.Background(), "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if id != "kc-acme" {
		t.Fatalf("id = %q", id)
	}
}

func TestOrganizationAttributes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/inari/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		case "/admin/realms/inari/organizations/kc-1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"kc-1","attributes":{"inari.plan.limits.v1":["{\"maxClusters\":0}"],"other":["keep"]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	admin := NewKeycloakAdmin(srv.URL, "inari", "client", "secret")
	attributes, err := admin.OrganizationAttributes(context.Background(), "kc-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := attributes["inari.plan.limits.v1"]; len(got) != 1 || got[0] != `{"maxClusters":0}` {
		t.Fatalf("attributes = %#v", attributes)
	}
	if got := attributes["other"]; len(got) != 1 || got[0] != "keep" {
		t.Fatalf("other attributes = %#v", attributes)
	}
}
