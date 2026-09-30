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
	"sync"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
)

// TestMemberEmailSearchEdgeCases probes adversarial inputs to the ?q=
// filter: ILIKE wildcard literals, backslashes, SQL-injection-shaped input,
// and the huma maxLength guard.
func TestMemberEmailSearchEdgeCases(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	idp.users["ann_1"] = true
	idp.users["alice"] = true
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	org, teams, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	var devTeamID string
	for _, tm := range teams {
		if tm.Name == "developers" {
			devTeamID = tm.ID
		}
	}
	if err := svc.AddMember(ctx, "user-1", "acme", "developers", "ann_1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMember(ctx, "user-1", "acme", "developers", "alice"); err != nil {
		t.Fatal(err)
	}

	// A bare _ must be literal, not a single-char wildcard: only ann_1's
	// email contains an underscore.
	members, err := svc.ListMembers(ctx, org.ID, devTeamID, "_")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].UserID != "ann_1" {
		t.Errorf("q=_ = %+v, want [ann_1] only (unescaped _ would match all)", members)
	}
	// Backslash input must not error and matches nothing.
	if members, err = svc.ListMembers(ctx, org.ID, devTeamID, `\`); err != nil || len(members) != 0 {
		t.Errorf(`q=\ = %+v, %v, want empty, nil`, members, err)
	}
	// SQL-injection-shaped input is parameterized: no error, no rows.
	if members, err = svc.ListMembers(ctx, org.ID, devTeamID, "'; DROP TABLE users;--"); err != nil || len(members) != 0 {
		t.Errorf("q=injection = %+v, %v, want empty, nil", members, err)
	}

	// HTTP level: maxLength 200 on q is enforced by huma validation.
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fixedValidator{id: &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}}, readyOK{})
	tenancy.NewHandler(svc, viewerAuthz{}).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/tenants/acme/members?q="+strings.Repeat("a", 201), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer good")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("q len 201: got %d, want 422", resp.StatusCode)
	}
}

// TestPlatformAdminsEdgeCases probes the platform admins API: unknown-email
// 404s, auth on the write verbs, and concurrent idempotent grants.
func TestPlatformAdminsEdgeCases(t *testing.T) {
	database := setupDB(t)
	idp := newFakeIdP()
	idp.users["admin-1"] = true
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())

	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fixedValidator{id: &authn.Identity{Subject: "user-1"}}, readyOK{})
	tenancy.NewPlatformHandler(svc, orgCreatorAuthz{}, "platform-admins").RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	call := func(method, url string, auth bool) int {
		req, err := http.NewRequest(method, srv.URL+url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if auth {
			req.Header.Set("Authorization", "Bearer good")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// Write verbs also require a token.
	if code := call(http.MethodPut, "/api/v1/platform/admins/admin-1", false); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated PUT: got %d, want 401", code)
	}
	if code := call(http.MethodDelete, "/api/v1/platform/admins/admin-1", false); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated DELETE: got %d, want 401", code)
	}
	// Unknown email subject -> 404 (not a 500 from the email fallback).
	if code := call(http.MethodPut, "/api/v1/platform/admins/ghost@example.com", true); code != http.StatusNotFound {
		t.Errorf("grant ghost@example.com: got %d, want 404", code)
	}
	if code := call(http.MethodDelete, "/api/v1/platform/admins/ghost@example.com", true); code != http.StatusNotFound {
		t.Errorf("revoke ghost@example.com: got %d, want 404", code)
	}
	// Concurrent grants of the same user are idempotent (Keycloak PUT is).
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- call(http.MethodPut, "/api/v1/platform/admins/admin-1", true)
		}()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusNoContent {
			t.Errorf("concurrent grant: got %d, want 204", code)
		}
	}
	// The list still resolves after the storm. (Membership uniqueness is
	// Keycloak's guarantee — PUT /users/{id}/groups/{gid} is a set union;
	// the fake IdP appends, so duplicates here are a fake artifact.)
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/platform/admins", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer good")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Admins []tenancy.PlatformAdminView `json:"admins"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Admins) == 0 || body.Admins[0].Email != "admin-1@example.com" {
		t.Errorf("admins after concurrent grants = %+v, want admin-1 present", body.Admins)
	}
}
