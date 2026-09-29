//go:build integration

package tenancy_test

import (
	"context"
	"encoding/json"
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
	"github.com/7K-Inari/inari-server/internal/types"
)

// viewerAuthz grants the org viewer relation to every caller (member lists
// are viewer-gated).
type viewerAuthz struct{}

func (viewerAuthz) Check(_ context.Context, _, relation, _ string) (bool, error) {
	return relation == authz.RelationViewer, nil
}
func (viewerAuthz) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

// TestMemberEmailSearch covers the ?q= email substring filter on the org and
// team member lists, at both the service/store level and the HTTP level
// (user picker for the access console).
func TestMemberEmailSearch(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	idp.users["alice"] = true
	idp.users["bob"] = true
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	org, teams, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	var devTeam types.Team
	for _, tm := range teams {
		if tm.Name == "developers" {
			devTeam = tm
		}
	}
	if err := svc.AddMember(ctx, "user-1", "acme", "developers", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMember(ctx, "user-1", "acme", "developers", "bob"); err != nil {
		t.Fatal(err)
	}

	// Store level: substring, case-insensitive.
	members, err := svc.ListMembers(ctx, org.ID, devTeam.ID, "ALICE")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].UserID != "alice" {
		t.Errorf("team members q=ALICE = %+v, want [alice]", members)
	}
	// No match.
	members, err = svc.ListMembers(ctx, org.ID, devTeam.ID, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 0 {
		t.Errorf("team members q=carol = %+v, want empty", members)
	}
	// Empty query returns everyone.
	members, err = svc.ListMembers(ctx, org.ID, devTeam.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 {
		t.Errorf("team members q= = %+v, want 2", members)
	}
	// A literal % must not act as a wildcard.
	members, err = svc.ListMembers(ctx, org.ID, devTeam.ID, "%")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 0 {
		t.Errorf("team members q=%% = %+v, want empty", members)
	}

	orgMembers, err := svc.ListOrgMembers(ctx, org.ID, "bob@")
	if err != nil {
		t.Fatal(err)
	}
	if len(orgMembers) != 1 || orgMembers[0].UserID != "bob" {
		t.Errorf("org members q=bob@ = %+v, want [bob]", orgMembers)
	}
	orgMembers, err = svc.ListOrgMembers(ctx, org.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(orgMembers) != 3 { // creator + alice + bob
		t.Errorf("org members q= = %+v, want 3", orgMembers)
	}

	// HTTP level: the query param reaches the store.
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fixedValidator{id: &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}}, readyOK{})
	tenancy.NewHandler(svc, viewerAuthz{}).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	get := func(url string) (int, map[string]json.RawMessage) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+url, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer good")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var body map[string]json.RawMessage
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body
	}

	code, body := get("/api/v1/tenants/acme/members?q=alice")
	if code != http.StatusOK {
		t.Fatalf("org members q=alice: got %d", code)
	}
	var orgOut []tenancy.OrgMemberView
	if err := json.Unmarshal(body["members"], &orgOut); err != nil {
		t.Fatal(err)
	}
	if len(orgOut) != 1 || orgOut[0].Email != "alice@example.com" {
		t.Errorf("org members q=alice = %+v", orgOut)
	}

	code, body = get("/api/v1/tenants/acme/teams/developers/members?q=bob")
	if code != http.StatusOK {
		t.Fatalf("team members q=bob: got %d", code)
	}
	var teamOut []tenancy.MemberView
	if err := json.Unmarshal(body["members"], &teamOut); err != nil {
		t.Fatal(err)
	}
	if len(teamOut) != 1 || teamOut[0].Email != "bob@example.com" {
		t.Errorf("team members q=bob = %+v", teamOut)
	}
}
