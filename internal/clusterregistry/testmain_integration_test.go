//go:build integration

package clusterregistry

import (
	"context"
	"os"
	"testing"

	"github.com/7K-Inari/inari-server/internal/testutil"
)

// TestMain pre-warms the shared testcontainers and tears them down after the
// package's tests run. Warm-up errors are ignored here: the per-test helpers
// still call the Shared* functions and skip via t.Skipf when testcontainers
// is unavailable.
func TestMain(m *testing.M) {
	ctx := context.Background()
	_, _ = testutil.SharedPostgres(ctx)
	code := m.Run()
	_ = testutil.TerminateShared(ctx)
	os.Exit(code)
}
