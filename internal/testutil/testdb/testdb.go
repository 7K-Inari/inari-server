// Package testdb bridges the shared testcontainers harness
// (internal/testutil) with internal/db: it creates a fresh database per test
// on the shared Postgres container, migrates it, and registers cleanup. It
// lives in its own package so packages under test (e.g. internal/db itself)
// can use the shared containers without an import cycle.
package testdb

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/testutil"
)

var dbSeq atomic.Uint64

// NewDatabase creates a fresh migrated database on the shared container and
// returns a handle to it, preserving the per-test isolation the previous
// per-test container pattern provided.
func NewDatabase(t *testing.T, pg *testutil.SharedPG) (*db.DB, error) {
	t.Helper()
	ctx := context.Background()

	dsn, err := pg.CreateDatabase(ctx, fmt.Sprintf("it_%d", dbSeq.Add(1)))
	if err != nil {
		return nil, err
	}
	database, err := db.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := database.Migrate(ctx); err != nil {
		database.Close()
		return nil, err
	}
	t.Cleanup(database.Close)
	return database, nil
}
