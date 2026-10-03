//go:build integration

package kubeproxy

import (
	"context"
	"os"
	"testing"

	"github.com/7K-Inari/inari-server/internal/testutil"
)

// TestMain pre-warms the shared testcontainers and tears them down after the
// package's tests run (per-package harness convention, AGENTS.md).
func TestMain(m *testing.M) {
	ctx := context.Background()
	_, _ = testutil.SharedPostgres(ctx)
	code := m.Run()
	_ = testutil.TerminateShared(ctx)
	os.Exit(code)
}
