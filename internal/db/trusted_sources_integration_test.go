//go:build integration

package db

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestTrustedSourcesDownIsExplicitlyIrreversible(t *testing.T) {
	dsn := startPostgres(t)
	const name = "irreversible_0041"
	createDatabase(t, dsn("inari"), name)
	ctx := context.Background()
	database, err := Connect(ctx, dsn(name))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO catalog_items
		(id, source, name, display_name, description, snapshot_present)
		VALUES ('template:legacy', 'template', 'legacy', 'Legacy', 'legacy', false)`); err != nil {
		t.Fatal(err)
	}
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDBFromPool(database.Pool)
	defer func() { _ = sqlDB.Close() }()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, sub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Down(ctx); err != nil {
		t.Fatalf("reversible 0042 Down failed before reaching 0041: %v", err)
	}
	if _, err := provider.Down(ctx); err == nil || !strings.Contains(err.Error(), "irreversible") {
		t.Fatalf("0041 Down error = %v, want explicit irreversible rejection", err)
	}
	var version int64
	if err := database.Pool.QueryRow(ctx, `SELECT max(version_id) FROM goose_db_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 41 {
		t.Fatalf("migration version after rejected Down = %d, want 41", version)
	}
	var present bool
	if err := database.Pool.QueryRow(ctx, `SELECT snapshot_present FROM catalog_items WHERE id='template:legacy'`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("rejected Down reactivated a legacy external item")
	}
}
