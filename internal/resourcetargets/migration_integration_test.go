//go:build integration

package resourcetargets_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
)

func TestMigrationBackfillsDeploymentTargetsAndRoleGrants(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}

	sqlDB := stdlib.OpenDBFromPool(database.Pool)
	defer sqlDB.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("../db/migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(ctx, 39); err != nil {
		t.Fatalf("down to 0039: %v", err)
	}

	if _, err := database.Pool.Exec(ctx, `INSERT INTO organizations (id, slug, display_name, keycloak_org_id)
		VALUES ('org:acme', 'acme', 'Acme', 'kc-acme')`); err != nil {
		t.Fatal(err)
	}
	seedTeam := func(name string, permissions string) string {
		t.Helper()
		var teamID string
		if err := database.Pool.QueryRow(ctx, `WITH r AS (
			INSERT INTO roles (org_id, name, display_name, permissions)
			VALUES ('org:acme', $1, $1, $2::jsonb) RETURNING id
		) INSERT INTO teams (org_id, name, role_id, keycloak_group_path)
		SELECT 'org:acme', $1, r.id, '/tenant-acme/' || $1 FROM r RETURNING id`, name, permissions).Scan(&teamID); err != nil {
			t.Fatal(err)
		}
		return teamID
	}
	devTeam := seedTeam("developers", `["tenant.read","deployments.create"]`)
	viewerTeam := seedTeam("viewers", `["tenant.read"]`)
	seedTeam("no-access", `[]`)
	for _, role := range []struct{ name, permissions string }{
		{"admin", `["tenant.read"]`},
		{"operator", `["tenant.read"]`},
	} {
		if _, err := database.Pool.Exec(ctx, `INSERT INTO roles (org_id, name, display_name, builtin, permissions)
			VALUES ('org:acme', $1, $1, true, $2::jsonb)`, role.name, role.permissions); err != nil {
			t.Fatal(err)
		}
	}
	for _, cluster := range []struct{ id, name, state string }{
		{"cluster:active", "active", "active"},
		{"cluster:pending", "pending", "pending_registration"},
		{"cluster:revoked", "revoked", "revoked"},
		{"cluster:decommissioned", "decommissioned", "decommissioned"},
	} {
		if _, err := database.Pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state)
			VALUES ($1, 'org:acme', $2, $3)`, cluster.id, cluster.name, cluster.state); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	var targets int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM resource_targets`).Scan(&targets); err != nil {
		t.Fatal(err)
	}
	if targets != 2 {
		t.Fatalf("backfilled targets = %d, want active and pending clusters only", targets)
	}
	var relation string
	if err := database.Pool.QueryRow(ctx, `SELECT g.relation FROM resource_target_grants g
		JOIN resource_targets rt ON rt.id = g.target_id
		WHERE rt.resource_id = 'cluster:active' AND g.team_id = $1`, devTeam).Scan(&relation); err != nil {
		t.Fatal(err)
	}
	if relation != "use" {
		t.Errorf("developer grant = %q, want use", relation)
	}
	if err := database.Pool.QueryRow(ctx, `SELECT g.relation FROM resource_target_grants g
		JOIN resource_targets rt ON rt.id = g.target_id
		WHERE rt.resource_id = 'cluster:active' AND g.team_id = $1`, viewerTeam).Scan(&relation); err != nil {
		t.Fatal(err)
	}
	if relation != "view" {
		t.Errorf("viewer grant = %q, want view", relation)
	}
	var monitoring int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM resource_targets WHERE capability = 'monitoring.grafana'`).Scan(&monitoring); err != nil {
		t.Fatal(err)
	}
	if monitoring != 0 {
		t.Errorf("monitoring targets = %d, want none", monitoring)
	}
	for _, role := range []string{"admin", "operator"} {
		var allowed bool
		if err := database.Pool.QueryRow(ctx, `SELECT permissions ? 'resourcetargets.manage' FROM roles
			WHERE org_id = 'org:acme' AND name = $1`, role).Scan(&allowed); err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Errorf("%s role missing resourcetargets.manage", role)
		}
	}
}
