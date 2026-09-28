//go:build integration

package eventbustest

import (
	"context"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
)

// Dispatcher builds an outbox dispatcher against a fresh embedded NATS
// server (JetStream, outbox stream ensured).
func Dispatcher(t *testing.T, database *db.DB, interval time.Duration, handlers ...audit.NamedHandler) *audit.Dispatcher {
	t.Helper()
	d, err := audit.NewDispatcher(context.Background(), database, Bus(t), interval, handlers)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}
	return d
}

// DispatchOnce is the synchronous drive path for tests: relay one batch of
// unpublished rows to JetStream, then drain all pending handler deliveries.
func DispatchOnce(ctx context.Context, d *audit.Dispatcher) error {
	if err := d.RelayOnce(ctx); err != nil {
		return err
	}
	_, err := d.DeliverOnce(ctx)
	return err
}
