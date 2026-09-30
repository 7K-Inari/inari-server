//go:build integration

package tenancy_test

import (
	"context"
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
				TeamID: team.ID, OrgID: org.ID, Role: team.Role, GroupPath: team.KeycloakGroupPath,
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
		members[0].DisplayName != "Ada Lovelace" || members[0].Role != string(types.RoleViewer) {
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

	// Invite flow grants org-admin via the anchor team.
	if err := svc.SetMemberRole(ctx, "admin", "acme", "kc-u1", types.RoleOrgAdmin); err != nil {
		t.Fatalf("SetMemberRole: %v", err)
	}
	// The IdP mapper also lands the user in the viewers group: the reconcile
	// adds the viewer row but must not touch the org-admin row.
	if err := svc.SyncTeamMembers(ctx, ref, []*types.User{{ID: "kc-u1"}}); err != nil {
		t.Fatalf("SyncTeamMembers: %v", err)
	}
	role, ok, err := tenancy.NewStore().HighestRole(ctx, database.Pool, org.ID, "kc-u1")
	if err != nil {
		t.Fatalf("HighestRole: %v", err)
	}
	if !ok || role != types.RoleOrgAdmin {
		t.Errorf("highest role = %q ok=%v, want org-admin (never downgrade)", role, ok)
	}

	// When the user leaves the viewers group, only the viewer row is
	// deleted; the org-admin membership survives.
	if err := svc.SyncTeamMembers(ctx, ref, nil); err != nil {
		t.Fatalf("SyncTeamMembers (empty): %v", err)
	}
	role, ok, err = tenancy.NewStore().HighestRole(ctx, database.Pool, org.ID, "kc-u1")
	if err != nil {
		t.Fatalf("HighestRole: %v", err)
	}
	if !ok || role != types.RoleOrgAdmin {
		t.Errorf("highest role after stale delete = %q ok=%v, want org-admin", role, ok)
	}
	if got := teamMembers(t, svc, org.ID, ref.TeamID); len(got) != 0 {
		t.Errorf("viewers members = %+v, want empty", got)
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
