//go:build integration

// Package eventbustest centralizes embedded-NATS setup for integration
// tests: an in-process nats-server with JetStream (no Docker container),
// plus helpers that bridge the outbox dispatcher's synchronous drive path.
package eventbustest

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"

	"github.com/7K-Inari/inari-server/internal/eventbus"
)

// ServerURL starts an embedded nats-server with JetStream enabled and
// returns its client URL.
func ServerURL(t *testing.T) string {
	t.Helper()
	s, err := server.NewServer(&server.Options{
		JetStream: true,
		StoreDir:  t.TempDir(),
		Host:      "127.0.0.1",
		Port:      -1,
	})
	if err != nil {
		t.Fatalf("nats-server: %v", err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats-server did not become ready")
	}
	t.Cleanup(s.Shutdown)
	return s.ClientURL()
}

// Bus connects a Bus to a fresh embedded server and ensures the outbox
// stream exists (R=1).
func Bus(t *testing.T) *eventbus.Bus {
	t.Helper()
	bus, err := eventbus.Connect(context.Background(), ServerURL(t),
		eventbus.WithConnectBudget(5*time.Second))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(bus.Close)
	if err := bus.EnsureOutboxStream(context.Background(), 1); err != nil {
		t.Fatalf("ensure stream: %v", err)
	}
	return bus
}
