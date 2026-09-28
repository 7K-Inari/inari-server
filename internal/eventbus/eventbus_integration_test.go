//go:build integration

package eventbus_test

import (
	"context"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/eventbus"
	"github.com/7K-Inari/inari-server/internal/eventbus/eventbustest"
)

func TestEnsureOutboxStreamIdempotent(t *testing.T) {
	ctx := context.Background()
	bus := eventbustest.Bus(t)
	if err := bus.EnsureOutboxStream(ctx, 1); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	s, err := bus.JetStream().Stream(ctx, eventbus.StreamNameOutbox)
	if err != nil {
		t.Fatalf("stream lookup: %v", err)
	}
	info, err := s.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.Duplicates != 24*time.Hour {
		t.Errorf("dedup window = %s, want 24h", info.Config.Duplicates)
	}
	if info.Config.MaxAge != 72*time.Hour {
		t.Errorf("max age = %s, want 72h", info.Config.MaxAge)
	}
}

func TestEphemeralPublishSubscribeRoundTrip(t *testing.T) {
	bus := eventbustest.Bus(t)
	subj, err := eventbus.TunnelSubject("cluster-1", "conn-9")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 1)
	unsub, err := bus.Subscribe(subj, func(_ string, data []byte) { got <- data })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unsub() }()

	frame := []byte("frame-payload")
	if err := eventbus.ValidateTunnelFrame(frame); err != nil {
		t.Fatal(err)
	}
	if err := bus.Publish(context.Background(), subj, frame); err != nil {
		t.Fatal(err)
	}
	select {
	case data := <-got:
		if string(data) != string(frame) {
			t.Errorf("got %q, want %q", data, frame)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no message received")
	}
}
