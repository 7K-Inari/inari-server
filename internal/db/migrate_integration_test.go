//go:build integration

package db

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3/lock"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// startPostgres launches a throwaway Postgres container and returns a DSN
// builder for any database name inside it.
func startPostgres(t *testing.T) func(dbName string) string {
	t.Helper()
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("inari"),
		postgres.WithUsername("inari"),
		postgres.WithPassword("inari"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
	)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	base, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	return func(dbName string) string {
		return strings.Replace(base, "/inari?", "/"+dbName+"?", 1)
	}
}

// createDatabase creates a fresh empty database inside the container reached
// by adminURL.
func createDatabase(t *testing.T, adminURL, name string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s", pgx.Identifier{name}.Sanitize())); err != nil {
		t.Fatal(err)
	}
}

// latestMigrationVersion is the highest version number embedded in
// internal/db/migrations.
func latestMigrationVersion(t *testing.T) int64 {
	t.Helper()
	var max int64
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		var v int64
		if _, err := fmt.Sscanf(e.Name(), "%04d_", &v); err == nil && v > max {
			max = v
		}
	}
	if max == 0 {
		t.Fatal("no migrations found")
	}
	return max
}

// TestMigrateConcurrentFreshBoot simulates two replicas first-booting against
// the same fresh database at the same time: both must serialize on the
// migration lock and converge on the latest schema version. Before the
// advisory-lock fix, one racer reliably failed with duplicate DDL errors.
func TestMigrateConcurrentFreshBoot(t *testing.T) {
	dsn := startPostgres(t)
	const attempts = 3
	for i := 0; i < attempts; i++ {
		name := fmt.Sprintf("race_%d", i)
		createDatabase(t, dsn("inari"), name)

		dbs := make([]*DB, 2)
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for r := 0; r < 2; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx := context.Background()
				database, err := Connect(ctx, dsn(name))
				if err != nil {
					errs[r] = err
					return
				}
				dbs[r] = database
				errs[r] = database.Migrate(ctx)
			}()
		}
		wg.Wait()
		for r := 0; r < 2; r++ {
			if errs[r] != nil {
				t.Fatalf("attempt %d replica %d: migrate: %v", i, r, errs[r])
			}
		}

		ctx := context.Background()
		var version int64
		if err := dbs[0].Pool.QueryRow(ctx, "SELECT max(version_id) FROM goose_db_version").Scan(&version); err != nil {
			t.Fatalf("attempt %d: read version: %v", i, err)
		}
		if want := latestMigrationVersion(t); version != want {
			t.Fatalf("attempt %d: version = %d, want %d", i, version, want)
		}
		for _, d := range dbs {
			d.Close()
		}
	}
}

// TestMigrateLockWaitTimeout pins the migration advisory lock from an outside
// session and asserts Migrate fails fast with a clear error instead of
// hanging; after the lock is released, Migrate succeeds.
func TestMigrateLockWaitTimeout(t *testing.T) {
	dsn := startPostgres(t)
	createDatabase(t, dsn("inari"), "lockwait")
	ctx := context.Background()

	holder, err := Connect(ctx, dsn("lockwait"))
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	conn, err := holder.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lock.DefaultLockID); err != nil {
		t.Fatal(err)
	}

	waiter, err := Connect(ctx, dsn("lockwait"))
	if err != nil {
		t.Fatal(err)
	}
	defer waiter.Close()
	start := time.Now()
	err = waiter.Migrate(ctx, WithLockWaitTimeout(6*time.Second))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("migrate succeeded while the advisory lock was held")
	}
	if !strings.Contains(err.Error(), "migration lock") {
		t.Fatalf("error does not name the migration lock: %v", err)
	}
	if elapsed > 30*time.Second {
		t.Fatalf("migrate did not fail fast: waited %s", elapsed)
	}

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", lock.DefaultLockID); err != nil {
		t.Fatal(err)
	}
	conn.Release()
	if err := waiter.Migrate(ctx); err != nil {
		t.Fatalf("migrate after unlock: %v", err)
	}
}
