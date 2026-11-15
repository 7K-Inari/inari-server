//go:build integration

package tenancy_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

func TestTeamDeletionSnapshotsExactTargetGrant(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	svc := tenancy.NewService(database, newFakeIdP(), tenancy.NewStore(), audit.NewStore())
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	roles, err := svc.ListRoles(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	var viewerRole string
	for _, role := range roles {
		if role.Name == "viewer" {
			viewerRole = role.ID
		}
	}
	team, err := svc.CreateTeam(ctx, "user-1", "acme", "temporary", viewerRole)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO resource_targets
		(id, org_id, name, resource_kind, resource_id, capability) VALUES
		('rt-team-delete', $1, 'shared', 'cluster', 'cluster:1', 'deployment.cluster')`, org.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO resource_target_grants (target_id, team_id, relation)
		VALUES ('rt-team-delete', $1, 'view')`, team.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteTeam(ctx, "user-1", "acme", "temporary"); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := database.Pool.QueryRow(ctx, `SELECT payload FROM outbox
		WHERE event_type='team.deleted' AND payload->>'teamId'=$1`, team.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var payload types.TeamCreatedPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.TargetGrants) != 1 || payload.TargetGrants[0].TargetID != "rt-team-delete" || payload.TargetGrants[0].Relation != "view" {
		t.Errorf("team deletion target grants = %+v", payload.TargetGrants)
	}
}

func TestTenantDeletionSnapshotIncludesExactTargetGrant(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	store := tenancy.NewStore()
	svc := tenancy.NewService(database, newFakeIdP(), store, audit.NewStore()).WithDeletionApprovalGate(&fakeGate{})
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	teams, err := svc.ListTeams(ctx, org.ID)
	if err != nil || len(teams) == 0 {
		t.Fatalf("teams = %v, %v", teams, err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO resource_targets
		(id, org_id, name, resource_kind, resource_id, capability) VALUES
		('rt-tenant-delete', $1, 'shared', 'cluster', 'cluster:1', 'monitoring.grafana')`, org.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO resource_target_grants (target_id, team_id, relation)
		VALUES ('rt-tenant-delete', $1, 'provision')`, teams[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DeleteTenant(ctx, "user-1", "acme", false, ""); err != nil {
		t.Fatal(err)
	}
	deletion, err := store.GetTenantDeletion(ctx, database.Pool, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot types.TenantDeletingPayload
	if err := json.Unmarshal(deletion.Snapshot, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.TargetGrants) != 1 || snapshot.TargetGrants[0].Relation != "provision" {
		t.Errorf("tenant target grants = %+v", snapshot.TargetGrants)
	}
	if len(snapshot.Objects["resource_target"]) != 1 || snapshot.Objects["resource_target"][0] != "rt-tenant-delete" {
		t.Errorf("tenant target objects = %+v", snapshot.Objects)
	}
}
