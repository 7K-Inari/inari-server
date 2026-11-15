//go:build integration

package capabilities

import (
	"context"
	"os"
	"testing"

	"github.com/7K-Inari/inari-server/internal/testutil"
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	_, _ = testutil.SharedPostgres(ctx)
	code := m.Run()
	_ = testutil.TerminateShared(ctx)
	os.Exit(code)
}
