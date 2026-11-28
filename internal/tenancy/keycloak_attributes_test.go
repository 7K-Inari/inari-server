package tenancy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpdateOrganizationAttributesPreservesRepresentation(t *testing.T) {
	var updated map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/realms/inari/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
		case r.URL.Path == "/admin/realms/inari/organizations/kc-1" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"kc-1","description":"Acme","domains":["acme.example"],"attributes":{"unrelated":["keep"]}}`))
		case r.URL.Path == "/admin/realms/inari/organizations/kc-1" && r.Method == http.MethodPut:
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	client := NewKeycloakAdmin(srv.URL, "inari", "inari-platform-admin", "test-secret")
	attributes := map[string][]string{"unrelated": {"keep"}, "inari.plan.limits.v1": {`{"allFeatures":true}`}}
	if err := client.UpdateOrganizationAttributes(context.Background(), "kc-1", attributes); err != nil {
		t.Fatal(err)
	}
	if updated["description"] != "Acme" || updated["id"] != "kc-1" {
		t.Fatalf("representation fields lost: %+v", updated)
	}
	domains, ok := updated["domains"].([]any)
	if !ok || len(domains) != 1 || domains[0] != "acme.example" {
		t.Fatalf("domains lost: %+v", updated["domains"])
	}
}
