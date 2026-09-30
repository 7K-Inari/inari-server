//go:build integration

package tenancy_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
)

// orgCreatorAuthz grants org_creator on platform:inari to every caller.
type orgCreatorAuthz struct{}

func (orgCreatorAuthz) Check(_ context.Context, _, relation, object string) (bool, error) {
	return relation == authz.RelationOrgCreator && object == authz.ObjectPlatform, nil
}
func (orgCreatorAuthz) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

// TestPlatformAdminsLifecycle exercises the platform admins API end-to-end:
// grant by UUID and by email, list with profiles, idempotent revoke, 404 on
// unknown subject, and audit rows. It must not write any FGA tuple (that is
// PlatformGroupSync's job).
func TestPlatformAdminsLifecycle(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	idp.users["admin-1"] = true
	idp.users["admin-2"] = true
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())

	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fixedValidator{id: &authn.Identity{Subject: "user-1"}}, readyOK{})
	tenancy.NewPlatformHandler(svc, orgCreatorAuthz{}, "platform-admins").RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	call := func(method, url string) (*http.Response, map[string]json.RawMessage) {
		req, err := http.NewRequest(method, srv.URL+url, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer good")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		var body map[string]json.RawMessage
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp, body
	}

	// Grant by UUID and by email (invite-style subject resolution).
	if resp, _ := call(http.MethodPut, "/api/v1/platform/admins/admin-1"); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("grant admin-1: got %d", resp.StatusCode)
	}
	// Re-granting an existing member is a no-op: 204 but no second audit row.
	if resp, _ := call(http.MethodPut, "/api/v1/platform/admins/admin-1"); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("re-grant admin-1: got %d", resp.StatusCode)
	}
	if resp, _ := call(http.MethodPut, "/api/v1/platform/admins/admin-2@example.com"); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("grant admin-2 by email: got %d", resp.StatusCode)
	}
	if got := idp.grpMembers["platform-admins"]; len(got) != 2 {
		t.Fatalf("group members = %v, want 2", got)
	}

	// List resolves user profiles.
	resp, body := call(http.MethodGet, "/api/v1/platform/admins")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d", resp.StatusCode)
	}
	var admins []tenancy.PlatformAdminView
	if err := json.Unmarshal(body["admins"], &admins); err != nil {
		t.Fatal(err)
	}
	if len(admins) != 2 || admins[0].Email == "" {
		t.Errorf("admins = %+v, want 2 with emails", admins)
	}

	// Unknown subject -> 404.
	if resp, _ := call(http.MethodPut, "/api/v1/platform/admins/ghost"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("grant ghost: got %d, want 404", resp.StatusCode)
	}

	// Revoke is idempotent: revoking twice succeeds.
	if resp, _ := call(http.MethodDelete, "/api/v1/platform/admins/admin-1"); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke admin-1: got %d", resp.StatusCode)
	}
	if resp, _ := call(http.MethodDelete, "/api/v1/platform/admins/admin-1"); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke admin-1 again: got %d", resp.StatusCode)
	}
	if got := idp.grpMembers["platform-admins"]; len(got) != 1 || got[0] != "admin-2" {
		t.Errorf("group members after revoke = %v, want [admin-2]", got)
	}

	// Audit rows: one row per effective change only — the duplicate grant
	// and the second (no-op) revoke above must not audit. Two grants +
	// one revoke under the platform scope.
	events, err := audit.NewStore().List(ctx, database.Pool, "platform", 10)
	if err != nil {
		t.Fatal(err)
	}
	var granted, revoked int
	for _, e := range events {
		switch e.Action {
		case "platform.admin.granted":
			granted++
		case "platform.admin.revoked":
			revoked++
		}
	}
	if granted != 2 || revoked != 1 {
		t.Errorf("audit granted=%d revoked=%d, want 2/1 (no-op grant/revoke must not audit)", granted, revoked)
	}
}

// TestPlatformAdminServiceNoFGATuples asserts the service layer performs no
// OpenFGA writes — PlatformGroupSync remains the single org_creator writer.
func TestPlatformAdminServiceNoFGATuples(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	idp.users["admin-1"] = true
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())

	if err := svc.GrantPlatformAdmin(ctx, "user-1", "platform-admins", "admin-1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokePlatformAdmin(ctx, "user-1", "platform-admins", "admin-1"); err != nil {
		t.Fatal(err)
	}
	// No outbox rows: nothing for TupleWriter to dispatch.
	var n int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("outbox rows = %d, want 0 (no FGA writes from platform admins API)", n)
	}
	if _, err := svc.ListPlatformAdmins(ctx, "platform-admins"); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("list: %v", err)
	}
}
