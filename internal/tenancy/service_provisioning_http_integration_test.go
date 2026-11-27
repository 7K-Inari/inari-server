//go:build integration

package tenancy_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

func TestTenantProvisioningHTTPIdentityMatrix(t *testing.T) {
	database := setupDB(t)
	idp := &ensureFakeIDP{newFakeIdP()}
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	identities := map[string]string{"tenant-provisioner": "service-1"}
	newServer := func(identity *authn.Identity, allow bool) *httptest.Server {
		router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), fixedValidator{id: identity}, readyOK{})
		tenancy.NewHandler(svc, allowOrgCreator{allow: allow}).WithTenantProvisioningIdentities(identities).RegisterRoutes(api)
		srv := httptest.NewServer(router)
		t.Cleanup(srv.Close)
		return srv
	}
	post := func(srv *httptest.Server, slug string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/tenants", strings.NewReader(`{"slug":"`+slug+`","displayName":"Acme"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer good")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}
	valid := &authn.Identity{Subject: "service-1", AuthorizedParty: "tenant-provisioner", Scopes: []string{"provisioning"}}
	srv := newServer(valid, true)
	resp := post(srv, "acme")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid M2M create = %d", resp.StatusCode)
	}
	var body struct {
		Organization types.Organization `json:"organization"`
		Teams        []types.Team       `json:"teams"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Teams) != 4 || len(idp.orgMembers[body.Organization.KeycloakOrgID]) != 0 {
		t.Fatalf("unexpected service membership: %+v", idp.orgMembers)
	}
	if replay := post(srv, "acme"); replay.StatusCode != http.StatusOK {
		t.Fatalf("replay = %d", replay.StatusCode)
	}
	for _, tc := range []struct {
		name     string
		identity *authn.Identity
		allow    bool
		slug     string
	}{
		{name: "missing scope", identity: &authn.Identity{Subject: "service-1", AuthorizedParty: "tenant-provisioner"}, allow: true, slug: "denied-scope"},
		{name: "wrong subject", identity: &authn.Identity{Subject: "user-1", AuthorizedParty: "tenant-provisioner", Scopes: []string{"provisioning"}}, allow: true, slug: "denied-subject"},
		{name: "missing org creator", identity: valid, allow: false, slug: "denied-fga"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if resp := post(newServer(tc.identity, tc.allow), tc.slug); resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
		})
	}
}
