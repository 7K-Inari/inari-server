//go:build integration

package tenancy_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// qaAdminAuthz grants org admin only to user-1 on the org it is asked about.
type qaAdminAuthz struct{ allow bool }

func (a qaAdminAuthz) Check(_ context.Context, _, relation, _ string) (bool, error) {
	return a.allow && relation == authz.RelationAdmin, nil
}
func (a qaAdminAuthz) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

// TestUpdateTeamHTTP exercises PUT /tenants/{org}/teams/{team} end-to-end:
// authz denial, unknown org/team, default-team 409, huma maxLength, happy path.
func TestUpdateTeamHTTP(t *testing.T) {
	database := setupDB(t)
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())

	mkServer := func(id *authn.Identity, allow bool) *httptest.Server {
		router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
			fixedValidator{id: id}, readyOK{})
		tenancy.NewHandler(svc, qaAdminAuthz{allow: allow}).RegisterRoutes(api)
		srv := httptest.NewServer(router)
		t.Cleanup(srv.Close)
		return srv
	}
	member := &authn.Identity{Subject: "user-1", Organizations: []string{"qa-org", "nope"}}
	outsider := &authn.Identity{Subject: "user-2", Organizations: []string{"elsewhere"}}

	if _, _, err := svc.CreateTenant(context.Background(), "user-1", "qa-org", "QA"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateTeam(context.Background(), "user-1", "qa-org", "custom", types.RoleDeveloper); err != nil {
		t.Fatal(err)
	}

	put := func(srv *httptest.Server, org, team, body string) *http.Response {
		req, err := http.NewRequest(http.MethodPut,
			srv.URL+"/api/v1/tenants/"+org+"/teams/"+team, strings.NewReader(body))
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

	srv := mkServer(member, true)

	// Not an org member -> 403.
	if resp := put(mkServer(outsider, true), "qa-org", "custom", `{"displayName":"X"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("outsider: got %d, want 403", resp.StatusCode)
	}
	// Member without admin tuple -> 403.
	if resp := put(mkServer(member, false), "qa-org", "custom", `{"displayName":"X"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin: got %d, want 403", resp.StatusCode)
	}
	// Unknown org -> 404 (member claim present but org missing).
	if resp := put(srv, "nope", "custom", `{"displayName":"X"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown org: got %d, want 404", resp.StatusCode)
	}
	// Unknown team -> 404.
	if resp := put(srv, "qa-org", "nope", `{"displayName":"X"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown team: got %d, want 404", resp.StatusCode)
	}
	// Default teams -> 409 (all four anchors).
	for _, anchor := range []string{"org-admins", "platform-team", "developers", "viewers"} {
		if resp := put(srv, "qa-org", anchor, `{"displayName":"X"}`); resp.StatusCode != http.StatusConflict {
			t.Errorf("default team %s: got %d, want 409", anchor, resp.StatusCode)
		}
	}
	// Over-long display name -> 422 (huma maxLength:200).
	long := `{"displayName":"` + strings.Repeat("x", 201) + `"}`
	if resp := put(srv, "qa-org", "custom", long); resp.StatusCode != http.StatusUnprocessableEntity {
		b, _ := io.ReadAll(resp.Body)
		t.Errorf("201 chars: got %d, want 422 (%s)", resp.StatusCode, b)
	}
	// Happy path -> 200, name + keycloak path unchanged.
	resp := put(srv, "qa-org", "custom", `{"displayName":"Custom Team"}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("happy path: got %d (%s)", resp.StatusCode, b)
	}
	var out struct {
		Team types.Team `json:"team"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Team.DisplayName != "Custom Team" || out.Team.Name != "custom" ||
		out.Team.KeycloakGroupPath != "tenant-qa-org/custom" {
		t.Errorf("response team = %+v", out.Team)
	}
	// The Keycloak group was not touched (path immutable, ADR-0007).
	if len(idp.groups) != 5 { // 4 anchors + custom
		t.Errorf("idp groups changed: %v", idp.groups)
	}
}
