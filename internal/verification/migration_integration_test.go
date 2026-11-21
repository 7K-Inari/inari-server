//go:build integration

package verification_test

import (
	"context"
	"os"
	"testing"

	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestEnvironmentVerificationMigrationUpDownUp(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewUnmigratedDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDBFromPool(database.Pool)
	defer sqlDB.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("../db/migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 42); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1');
		INSERT INTO clusters (id, org_id, name, state) VALUES ('cluster:1','org:1','kind','active');
		INSERT INTO resource_instances (id, org_id, cluster_id, catalog_item_id, version, spec) VALUES ('inst-1','org:1','cluster:1','item','1.0.0','{}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 44); err != nil {
		t.Fatalf("up to 0044: %v", err)
	}
	var uid string
	if err := database.Pool.QueryRow(ctx, `SELECT uid FROM resource_instances WHERE id='inst-1'`).Scan(&uid); err != nil || uid == "" {
		t.Fatalf("backfilled instance UID = %q, %v", uid, err)
	}
	var tables int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name LIKE 'verification_%'`).Scan(&tables); err != nil || tables != 8 {
		t.Fatalf("verification tables = %d, %v", tables, err)
	}
	if _, err := provider.DownTo(ctx, 42); err != nil {
		t.Fatalf("down to 0042: %v", err)
	}
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name LIKE 'verification_%'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("tables after down = %d, %v", tables, err)
	}
	if _, err := provider.UpTo(ctx, 44); err != nil {
		t.Fatalf("second up to 0044: %v", err)
	}
}
