//go:build integration

package tenancy_test

import (
	"context"
	"slices"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// setupProjectionTenant creates a tenant and returns the service plus the
// viewers anchor team ref used by the projection tests.
func setupProjectionTenant(t *testing.T) (context.Context, *db.DB, *tenancy.Service, *fakeIdP, *types.Organization, authz.TeamGroupRef) {
	t.Helper()
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	org, teams, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme Corp")
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	for _, team := range teams {
		if team.Name == "viewers" {
			return ctx, database, svc, idp, org, authz.TeamGroupRef{
				TeamID: team.ID, OrgID: org.ID, RoleID: team.RoleID, Permissions: []string{"tenant.read"}, GroupPath: team.KeycloakGroupPath,
			}
		}
	}
	t.Fatal("viewers anchor team not found")
	return nil, nil, nil, nil, nil, authz.TeamGroupRef{}
}

func outboxCount(t *testing.T, database *db.DB) int {
	t.Helper()
	var n int
	if err := database.Pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox`).Scan(&n); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	return n
}

func teamMembers(t *testing.T, svc *tenancy.Service, orgID, teamID string) []tenancy.MemberView {
	t.Helper()
	members, err := svc.ListMembers(context.Background(), orgID, teamID, "")
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	return members
}

func TestSyncTeamMembersUpsert(t *testing.T) {
	ctx, _, svc, _, org, ref := setupProjectionTenant(t)

	users := []*types.User{
		{ID: "kc-u1", Email: "ada@example.com", DisplayName: "Ada Lovelace"},
		{ID: "kc-u2", Email: "bob@example.com"},
	}
	if err := svc.SyncTeamMembers(ctx, ref, users); err != nil {
		t.Fatalf("SyncTeamMembers: %v", err)
	}
	members := teamMembers(t, svc, org.ID, ref.TeamID)
	if len(members) != 2 {
		t.Fatalf("members = %+v, want 2", members)
	}
	if members[0].UserID != "kc-u1" || members[0].Email != "ada@example.com" ||
		members[0].DisplayName != "Ada Lovelace" || members[0].Role != "viewer" {
		t.Errorf("members[0] = %+v, want projected kc-u1 viewer", members[0])
	}
	if members[1].UserID != "kc-u2" || members[1].Email != "bob@example.com" {
		t.Errorf("members[1] = %+v, want projected kc-u2", members[1])
	}

	// Idempotent: a second pass with the same set changes nothing.
	if err := svc.SyncTeamMembers(ctx, ref, users); err != nil {
		t.Fatalf("SyncTeamMembers (2nd): %v", err)
	}
	if got := teamMembers(t, svc, org.ID, ref.TeamID); len(got) != 2 {
		t.Errorf("members after 2nd pass = %+v, want unchanged 2", got)
	}

	// A later pass whose Keycloak payload lacks email/display name (IdP
	// mapper gap) must not erase the profile fields stored earlier.
	if err := svc.SyncTeamMembers(ctx, ref, []*types.User{{ID: "kc-u1"}, {ID: "kc-u2"}}); err != nil {
		t.Fatalf("SyncTeamMembers (sparse): %v", err)
	}
	members = teamMembers(t, svc, org.ID, ref.TeamID)
	if members[0].Email != "ada@example.com" || members[0].DisplayName != "Ada Lovelace" {
		t.Errorf("members[0] after sparse pass = %+v, want profile preserved", members[0])
	}
	if members[1].Email != "bob@example.com" {
		t.Errorf("members[1] after sparse pass = %+v, want email preserved", members[1])
	}
}

func TestSyncTeamMembersDeletesStale(t *testing.T) {
	ctx, database, svc, idp, org, ref := setupProjectionTenant(t)
	idp.users["kc-u2"] = true

	if err := svc.SyncTeamMembers(ctx, ref, []*types.User{{ID: "kc-u1"}, {ID: "kc-u2"}}); err != nil {
		t.Fatalf("SyncTeamMembers: %v", err)
	}
	// kc-u2 also holds a membership on another team (invite flow).
	if err := svc.AddMember(ctx, "admin", "acme", "developers", "kc-u2"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	// kc-u2 leaves the Keycloak group: only its row on THIS team goes away.
	if err := svc.SyncTeamMembers(ctx, ref, []*types.User{{ID: "kc-u1"}}); err != nil {
		t.Fatalf("SyncTeamMembers (stale): %v", err)
	}
	members := teamMembers(t, svc, org.ID, ref.TeamID)
	if len(members) != 1 || members[0].UserID != "kc-u1" {
		t.Errorf("members = %+v, want only kc-u1", members)
	}
	devs, err := svc.ListMembers(ctx, org.ID, teamIDByName(t, database, org.ID, "developers"), "")
	if err != nil {
		t.Fatalf("ListMembers developers: %v", err)
	}
	if len(devs) != 1 || devs[0].UserID != "kc-u2" {
		t.Errorf("developers members = %+v, want kc-u2 row preserved", devs)
	}
}

func TestSyncTeamMembersConflictWithInvite(t *testing.T) {
	ctx, database, svc, idp, org, ref := setupProjectionTenant(t)
	idp.users["kc-u1"] = true

	// Invite flow first, then reconcile: no error, no duplicate, and the
	// projection emits no outbox events of its own.
	if err := svc.AddMember(ctx, "admin", "acme", "viewers", "kc-u1"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	before := outboxCount(t, database)
	if err := svc.SyncTeamMembers(ctx, ref, []*types.User{{ID: "kc-u1", Email: "kc-u1@example.com"}}); err != nil {
		t.Fatalf("SyncTeamMembers: %v", err)
	}
	if got := teamMembers(t, svc, org.ID, ref.TeamID); len(got) != 1 {
		t.Errorf("members = %+v, want exactly 1 row", got)
	}
	if got := outboxCount(t, database); got != before {
		t.Errorf("outbox rows = %d, want unchanged %d (projection must not emit events)", got, before)
	}

	// Reverse order: reconcile first, then invite — still exactly one row.
	if err := svc.SyncTeamMembers(ctx, ref, []*types.User{{ID: "kc-u3"}}); err != nil {
		t.Fatalf("SyncTeamMembers (kc-u3): %v", err)
	}
	idp.users["kc-u3"] = true
	if err := svc.AddMember(ctx, "admin", "acme", "viewers", "kc-u3"); err != nil {
		t.Fatalf("AddMember (kc-u3): %v", err)
	}
	var rows int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM memberships WHERE org_id=$1 AND team_id=$2 AND user_id='kc-u3'`,
		org.ID, ref.TeamID).Scan(&rows); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if rows != 1 {
		t.Errorf("membership rows for kc-u3 = %d, want 1", rows)
	}
}

func TestSyncTeamMembersNeverDowngrades(t *testing.T) {
	ctx, database, svc, idp, org, ref := setupProjectionTenant(t)
	idp.users["kc-u1"] = true

	// Invite flow grants the admin role via the anchor team.
	if err := svc.SetMemberRole(ctx, "admin", "acme", "kc-u1", "admin"); err != nil {
		t.Fatalf("SetMemberRole: %v", err)
	}
	// The IdP mapper also lands the user in the viewers group: the reconcile
	// adds the viewer row but must not touch the admin row.
	if err := svc.SyncTeamMembers(ctx, ref, []*types.User{{ID: "kc-u1"}}); err != nil {
		t.Fatalf("SyncTeamMembers: %v", err)
	}
	store := tenancy.NewStore()
	isAdmin, err := store.HasPermission(ctx, database.Pool, org.ID, "kc-u1", "tenant.admin")
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}
	if !isAdmin {
		t.Error("tenant.admin lost after projection sync (never downgrade)")
	}

	// When the user leaves the viewers group, only the viewer row is
	// deleted; the admin membership survives.
	if err := svc.SyncTeamMembers(ctx, ref, nil); err != nil {
		t.Fatalf("SyncTeamMembers (empty): %v", err)
	}
	isAdmin, err = store.HasPermission(ctx, database.Pool, org.ID, "kc-u1", "tenant.admin")
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}
	if !isAdmin {
		t.Error("tenant.admin lost after stale delete")
	}
	if got := teamMembers(t, svc, org.ID, ref.TeamID); len(got) != 0 {
		t.Errorf("viewers members = %+v, want empty", got)
	}
}

// Duplicate entries in the Keycloak member list (defensive: the Admin API
// should not produce them) collapse to one row and keep the user in the
// keep set.
func TestSyncTeamMembersDuplicateEntries(t *testing.T) {
	ctx, _, svc, _, org, ref := setupProjectionTenant(t)

	dup := &types.User{ID: "kc-u1", Email: "ada@example.com"}
	if err := svc.SyncTeamMembers(ctx, ref, []*types.User{dup, dup}); err != nil {
		t.Fatalf("SyncTeamMembers: %v", err)
	}
	if got := teamMembers(t, svc, org.ID, ref.TeamID); len(got) != 1 {
		t.Errorf("members = %+v, want exactly 1 row for duplicated input", got)
	}
}

// The reconcile projection and the invite flow racing on the same user
// must converge to exactly one membership row, with no error on either
// side (plan risk 6: projection vs invite flow interaction).
func TestSyncTeamMembersConcurrentWithInvite(t *testing.T) {
	ctx, database, svc, idp, org, ref := setupProjectionTenant(t)
	idp.users["kc-u9"] = true

	const racers = 8
	errs := make(chan error, 2*racers)
	for i := 0; i < racers; i++ {
		go func() {
			errs <- svc.SyncTeamMembers(ctx, ref, []*types.User{{ID: "kc-u9", Email: "nine@example.com"}})
		}()
		go func() {
			// AddMember is idempotent by design (same-PK upsert); concurrent
			// repeats race the projection the way an invite retry would.
			errs <- svc.AddMember(ctx, "admin", "acme", "viewers", "kc-u9")
		}()
	}
	for i := 0; i < 2*racers; i++ {
		if err := <-errs; err != nil {
			t.Errorf("racer error: %v", err)
		}
	}
	var rows int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM memberships WHERE org_id=$1 AND team_id=$2 AND user_id='kc-u9'`,
		org.ID, ref.TeamID).Scan(&rows); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if rows != 1 {
		t.Errorf("membership rows for kc-u9 = %d, want exactly 1 after concurrent writers", rows)
	}
}

func teamIDByName(t *testing.T, database *db.DB, orgID, name string) string {
	t.Helper()
	team, err := tenancy.NewStore().GetTeamByName(context.Background(), database.Pool, orgID, name)
	if err != nil {
		t.Fatalf("GetTeamByName: %v", err)
	}
	return team.ID
}

// TestSyncTeamMembersConvergesAfterRoleChange reproduces B8: when a team's
// role mapping is flipped (editor -> operator -> editor), the membership
// projection must converge to exactly the current team role and not leave
// stale rows for the old role.
func TestSyncTeamMembersConvergesAfterRoleChange(t *testing.T) {
	ctx, _, svc, idp, org, _ := setupProjectionTenant(t)
	idp.users["dev-user"] = true

	teams, err := svc.ListTeams(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListTeams: %v", err)
	}
	var devTeam *types.Team
	for i := range teams {
		if teams[i].Name == "developers" {
			devTeam = &teams[i]
			break
		}
	}
	if devTeam == nil {
		t.Fatal("developers team not found")
	}

	if err := svc.AddMember(ctx, "admin", "acme", "developers", "dev-user"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	names, err := svc.ListMemberRoleNames(ctx, org.ID, "dev-user")
	if err != nil {
		t.Fatalf("ListMemberRoleNames initial: %v", err)
	}
	if !slices.Contains(names, "editor") || len(names) != 1 {
		t.Fatalf("initial roles = %v, want [editor]", names)
	}

	operator, err := svc.GetRole(ctx, "acme", "operator")
	if err != nil {
		t.Fatalf("GetRole operator: %v", err)
	}
	editor, err := svc.GetRole(ctx, "acme", "editor")
	if err != nil {
		t.Fatalf("GetRole editor: %v", err)
	}

	// Flip developers to operator.
	if _, err := svc.SetRBACMappings(ctx, "admin", "acme", []types.TeamRoleMapping{
		{Team: "developers", RoleID: operator.ID},
	}); err != nil {
		t.Fatalf("SetRBACMappings operator: %v", err)
	}
	if err := svc.SyncTeamMembers(ctx, authz.TeamGroupRef{
		TeamID: devTeam.ID, OrgID: org.ID, RoleID: operator.ID, GroupPath: devTeam.KeycloakGroupPath,
	}, []*types.User{{ID: "dev-user", Email: "dev-user@example.com"}}); err != nil {
		t.Fatalf("SyncTeamMembers operator: %v", err)
	}
	names, err = svc.ListMemberRoleNames(ctx, org.ID, "dev-user")
	if err != nil {
		t.Fatalf("ListMemberRoleNames operator: %v", err)
	}
	if len(names) != 1 || names[0] != "operator" {
		t.Errorf("after operator sync roles = %v, want [operator]", names)
	}
	members := teamMembers(t, svc, org.ID, devTeam.ID)
	if len(members) != 1 || members[0].Role != "operator" {
		t.Errorf("after operator sync team members = %+v, want 1 operator", members)
	}

	// Flip developers back to editor.
	if _, err := svc.SetRBACMappings(ctx, "admin", "acme", []types.TeamRoleMapping{
		{Team: "developers", RoleID: editor.ID},
	}); err != nil {
		t.Fatalf("SetRBACMappings editor: %v", err)
	}
	if err := svc.SyncTeamMembers(ctx, authz.TeamGroupRef{
		TeamID: devTeam.ID, OrgID: org.ID, RoleID: editor.ID, GroupPath: devTeam.KeycloakGroupPath,
	}, []*types.User{{ID: "dev-user", Email: "dev-user@example.com"}}); err != nil {
		t.Fatalf("SyncTeamMembers editor: %v", err)
	}
	names, err = svc.ListMemberRoleNames(ctx, org.ID, "dev-user")
	if err != nil {
		t.Fatalf("ListMemberRoleNames editor: %v", err)
	}
	if len(names) != 1 || names[0] != "editor" {
		t.Errorf("after editor sync roles = %v, want [editor]", names)
	}
	members = teamMembers(t, svc, org.ID, devTeam.ID)
	if len(members) != 1 || members[0].Role != "editor" {
		t.Errorf("after editor sync team members = %+v, want 1 editor", members)
	}
}

// TestSetMemberRoleConvergesWithRemappedAnchor reproduces the second half of
// B8: when the editor anchor team (developers) is remapped to operator via
// PUT /rbac/mappings, a subsequent PUT /members/{subject} role=editor must not
// leave a duplicate "editor" membership row. The effective role follows the
// team's current mapping, and the projection converges to a single row.
func TestSetMemberRoleConvergesWithRemappedAnchor(t *testing.T) {
	ctx, _, svc, idp, org, _ := setupProjectionTenant(t)
	idp.users["dev-user"] = true

	operator, err := svc.GetRole(ctx, "acme", "operator")
	if err != nil {
		t.Fatalf("GetRole operator: %v", err)
	}

	if _, err := svc.SetRBACMappings(ctx, "admin", "acme", []types.TeamRoleMapping{
		{Team: "developers", RoleID: operator.ID},
	}); err != nil {
		t.Fatalf("SetRBACMappings operator: %v", err)
	}

	// Request "editor"; the anchor team is developers, which now grants operator.
	if err := svc.SetMemberRole(ctx, "admin", "acme", "dev-user", "editor"); err != nil {
		t.Fatalf("SetMemberRole editor: %v", err)
	}

	names, err := svc.ListMemberRoleNames(ctx, org.ID, "dev-user")
	if err != nil {
		t.Fatalf("ListMemberRoleNames: %v", err)
	}
	if len(names) != 1 || names[0] != "operator" {
		t.Errorf("after SetMemberRole roles = %v, want [operator]", names)
	}

	teams, err := svc.ListTeams(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListTeams: %v", err)
	}
	var devTeam *types.Team
	for i := range teams {
		if teams[i].Name == "developers" {
			devTeam = &teams[i]
			break
		}
	}
	if devTeam == nil {
		t.Fatal("developers team not found")
	}

	// A sync pass must not introduce a duplicate.
	if err := svc.SyncTeamMembers(ctx, authz.TeamGroupRef{
		TeamID: devTeam.ID, OrgID: org.ID, RoleID: operator.ID, GroupPath: devTeam.KeycloakGroupPath,
	}, []*types.User{{ID: "dev-user", Email: "dev-user@example.com"}}); err != nil {
		t.Fatalf("SyncTeamMembers: %v", err)
	}
	names, err = svc.ListMemberRoleNames(ctx, org.ID, "dev-user")
	if err != nil {
		t.Fatalf("ListMemberRoleNames after sync: %v", err)
	}
	if len(names) != 1 || names[0] != "operator" {
		t.Errorf("after sync roles = %v, want [operator]", names)
	}
}

// TestSyncTeamMembersConvergesRoleChangeWithMultipleUsers verifies that a
// team role change cleans stale rows for every member of the team, not just
// one, and that simultaneous leavers are also removed.
func TestSyncTeamMembersConvergesRoleChangeWithMultipleUsers(t *testing.T) {
	ctx, _, svc, idp, org, _ := setupProjectionTenant(t)
	idp.users["dev-1"] = true
	idp.users["dev-2"] = true
	idp.users["dev-3"] = true

	teams, err := svc.ListTeams(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListTeams: %v", err)
	}
	var devTeam *types.Team
	for i := range teams {
		if teams[i].Name == "developers" {
			devTeam = &teams[i]
			break
		}
	}
	if devTeam == nil {
		t.Fatal("developers team not found")
	}

	for _, u := range []string{"dev-1", "dev-2", "dev-3"} {
		if err := svc.AddMember(ctx, "admin", "acme", "developers", u); err != nil {
			t.Fatalf("AddMember %s: %v", u, err)
		}
	}

	operator, err := svc.GetRole(ctx, "acme", "operator")
	if err != nil {
		t.Fatalf("GetRole operator: %v", err)
	}
	if _, err := svc.SetRBACMappings(ctx, "admin", "acme", []types.TeamRoleMapping{
		{Team: "developers", RoleID: operator.ID},
	}); err != nil {
		t.Fatalf("SetRBACMappings operator: %v", err)
	}

	// dev-3 leaves the group at the same time the role changes.
	if err := svc.SyncTeamMembers(ctx, authz.TeamGroupRef{
		TeamID: devTeam.ID, OrgID: org.ID, RoleID: operator.ID, GroupPath: devTeam.KeycloakGroupPath,
	}, []*types.User{
		{ID: "dev-1", Email: "dev-1@example.com"},
		{ID: "dev-2", Email: "dev-2@example.com"},
	}); err != nil {
		t.Fatalf("SyncTeamMembers operator: %v", err)
	}

	for _, u := range []string{"dev-1", "dev-2"} {
		names, err := svc.ListMemberRoleNames(ctx, org.ID, u)
		if err != nil {
			t.Fatalf("ListMemberRoleNames %s: %v", u, err)
		}
		if len(names) != 1 || names[0] != "operator" {
			t.Errorf("%s roles = %v, want [operator]", u, names)
		}
	}
	// dev-3 should have no roles left from this team.
	names, err := svc.ListMemberRoleNames(ctx, org.ID, "dev-3")
	if err != nil {
		t.Fatalf("ListMemberRoleNames dev-3: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("dev-3 roles = %v, want []", names)
	}

	members := teamMembers(t, svc, org.ID, devTeam.ID)
	if len(members) != 2 {
		t.Errorf("team members = %+v, want 2", members)
	}
}

// TestSyncTeamMembersEmptyGroupAfterRoleChange verifies that when a team's
// role changes and the Keycloak group is simultaneously empty, every stale
// membership row for that team is removed. This exercises the SQL semantic
// that user_id <> ALL(ARRAY[]::text[]) is true for all rows.
func TestSyncTeamMembersEmptyGroupAfterRoleChange(t *testing.T) {
	ctx, _, svc, idp, org, _ := setupProjectionTenant(t)
	idp.users["dev-user"] = true

	teams, err := svc.ListTeams(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListTeams: %v", err)
	}
	var devTeam *types.Team
	for i := range teams {
		if teams[i].Name == "developers" {
			devTeam = &teams[i]
			break
		}
	}
	if devTeam == nil {
		t.Fatal("developers team not found")
	}

	if err := svc.AddMember(ctx, "admin", "acme", "developers", "dev-user"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	operator, err := svc.GetRole(ctx, "acme", "operator")
	if err != nil {
		t.Fatalf("GetRole operator: %v", err)
	}
	if _, err := svc.SetRBACMappings(ctx, "admin", "acme", []types.TeamRoleMapping{
		{Team: "developers", RoleID: operator.ID},
	}); err != nil {
		t.Fatalf("SetRBACMappings operator: %v", err)
	}

	// Empty Keycloak group after the role flip: the team should have no members.
	if err := svc.SyncTeamMembers(ctx, authz.TeamGroupRef{
		TeamID: devTeam.ID, OrgID: org.ID, RoleID: operator.ID, GroupPath: devTeam.KeycloakGroupPath,
	}, nil); err != nil {
		t.Fatalf("SyncTeamMembers empty: %v", err)
	}

	names, err := svc.ListMemberRoleNames(ctx, org.ID, "dev-user")
	if err != nil {
		t.Fatalf("ListMemberRoleNames: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("dev-user roles = %v, want []", names)
	}
	if got := teamMembers(t, svc, org.ID, devTeam.ID); len(got) != 0 {
		t.Errorf("team members = %+v, want empty", got)
	}
}
