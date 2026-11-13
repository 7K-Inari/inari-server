//go:build integration

package resourcetargets

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
)

func setupStore(t *testing.T) (*db.DB, context.Context, string, string) {
	t.Helper()
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO organizations (id, slug, display_name, keycloak_org_id)
		VALUES ('org:store', 'store', 'Store', 'kc-store'), ('org:other', 'other', 'Other', 'kc-other')`); err != nil {
		t.Fatal(err)
	}
	var roleID, teamID string
	if err := database.Pool.QueryRow(ctx, `INSERT INTO roles (org_id, name, display_name, permissions)
		VALUES ('org:store', 'custom', 'Custom', '["tenant.read","deployments.create"]') RETURNING id`).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool.QueryRow(ctx, `INSERT INTO teams (org_id, name, role_id, keycloak_group_path)
		VALUES ('org:store', 'developers', $1, '/tenant-store/developers') RETURNING id`, roleID).Scan(&teamID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO users (id) VALUES ('alice')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO memberships (user_id, org_id, team_id, role_id)
		VALUES ('alice', 'org:store', $1, $2)`, teamID, roleID); err != nil {
		t.Fatal(err)
	}
	return database, ctx, teamID, roleID
}

func testTarget(id string) *Target {
	return &Target{
		ID: id, OrgID: "org:store", Name: "shared", ResourceRef: ResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capabilities: []string{CapabilityDeploymentCluster}, Config: json.RawMessage(`{}`), Enabled: true, Revision: 1,
	}
}

func TestStoreTargetRevisionAndGrantFence(t *testing.T) {
	database, ctx, teamID, _ := setupStore(t)
	s := NewStore()
	target := testTarget("target-1")
	if err := s.Create(ctx, database.Pool, target); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get(ctx, database.Pool, target.OrgID, target.ID)
	if err != nil {
		t.Fatalf("created target was not persisted: %v", err)
	}
	if got.Revision != 1 || got.Capability() != CapabilityDeploymentCluster {
		t.Errorf("got = %+v", got)
	}
	if _, err := s.Get(ctx, database.Pool, "org:other", target.ID); !errors.Is(err, ErrTargetNotFound) {
		t.Errorf("cross-org get = %v, want not found", err)
	}
	byResource, err := s.GetByResource(ctx, database.Pool, target.OrgID, CapabilityDeploymentCluster, target.ResourceRef)
	if err != nil || byResource.ID != target.ID {
		t.Fatalf("get by resource = %+v, %v", byResource, err)
	}

	got.Name = "renamed"
	if err := s.Update(ctx, database.Pool, got, 0); !errors.Is(err, ErrStaleRevision) {
		t.Errorf("stale update = %v, want ErrStaleRevision", err)
	}
	if err := s.Update(ctx, database.Pool, got, 1); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.Revision != 2 {
		t.Errorf("revision = %d, want 2", got.Revision)
	}

	grant := &Grant{TargetID: target.ID, TeamID: teamID, Relation: ActionUse, CreatedBy: "user:admin"}
	if err := s.SetGrant(ctx, database.Pool, grant); err != nil {
		t.Fatalf("set grant: %v", err)
	}
	allowed, err := s.GrantAllows(ctx, database.Pool, target.OrgID, "alice", []string{target.ID}, ActionUse)
	if err != nil || !allowed[target.ID] {
		t.Errorf("use fence = %v, %v", allowed, err)
	}
	allowed, err = s.GrantAllows(ctx, database.Pool, target.OrgID, "alice", []string{target.ID}, ActionProvision)
	if err != nil || allowed[target.ID] {
		t.Errorf("use grant must not satisfy provision: %v, %v", allowed, err)
	}
	grant.Relation = ActionView
	if err := s.SetGrant(ctx, database.Pool, grant); err != nil {
		t.Fatal(err)
	}
	allowed, err = s.GrantAllows(ctx, database.Pool, target.OrgID, "alice", []string{target.ID}, ActionUse)
	if err != nil || allowed[target.ID] {
		t.Errorf("downgraded grant still allows use: %v, %v", allowed, err)
	}
	if err := s.DeleteGrant(ctx, database.Pool, target.OrgID, target.ID, teamID); err != nil {
		t.Fatal(err)
	}
	allowed, err = s.GrantAllows(ctx, database.Pool, target.OrgID, "alice", []string{target.ID}, ActionView)
	if err != nil || allowed[target.ID] {
		t.Errorf("revoked grant still allows view: %v, %v", allowed, err)
	}
}

func TestStoreRejectsDuplicateAndRevocationSurvivesStaleFGA(t *testing.T) {
	database, ctx, teamID, _ := setupStore(t)
	s := NewStore()
	if err := s.Create(ctx, database.Pool, testTarget("target-1")); err != nil {
		t.Fatal(err)
	}
	duplicate := testTarget("target-2")
	if err := s.Create(ctx, database.Pool, duplicate); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate resource = %v, want conflict", err)
	}
	if err := s.SetGrant(ctx, database.Pool, &Grant{TargetID: "target-1", TeamID: teamID, Relation: ActionUse}); err != nil {
		t.Fatal(err)
	}
	// Deleting the DB grant is an immediate deny fence even when an
	// authorization cache still holds a previous allow.
	if err := s.DeleteGrant(ctx, database.Pool, "org:store", "target-1", teamID); err != nil {
		t.Fatal(err)
	}
	allowed, err := s.GrantAllows(ctx, database.Pool, "org:store", "alice", []string{"target-1"}, ActionUse)
	if err != nil {
		t.Fatal(err)
	}
	if allowed["target-1"] {
		t.Fatal("stale cached allow must not bypass a deleted DB grant")
	}
}
