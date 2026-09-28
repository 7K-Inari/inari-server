package eventbus_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/eventbus"
)

func TestOutboxSubject(t *testing.T) {
	if got := eventbus.OutboxSubject("tenant.created"); got != "inari.outbox.tenant.created" {
		t.Errorf("OutboxSubject = %q", got)
	}
}

func TestValidateSubjectToken(t *testing.T) {
	valid := []string{"cluster-abc", "conn-123", "a", "UPPER_ok"}
	for _, s := range valid {
		if err := eventbus.ValidateSubjectToken(s); err != nil {
			t.Errorf("ValidateSubjectToken(%q) = %v, want nil", s, err)
		}
	}
	invalid := []string{"", "has.dot", "has*star", "has>gt", "has space", "has\ttab"}
	for _, s := range invalid {
		if err := eventbus.ValidateSubjectToken(s); err == nil {
			t.Errorf("ValidateSubjectToken(%q) = nil, want error", s)
		}
	}
}

func TestTunnelSubject(t *testing.T) {
	got, err := eventbus.TunnelSubject("cluster-1", "conn-9")
	if err != nil {
		t.Fatal(err)
	}
	if got != "inari.tunnel.cluster-1.conn-9" {
		t.Errorf("TunnelSubject = %q", got)
	}
	if _, err := eventbus.TunnelSubject("bad.id", "conn-9"); err == nil {
		t.Error("TunnelSubject with dotted clusterID = nil error")
	}
	if _, err := eventbus.TunnelSubject("cluster-1", ""); err == nil {
		t.Error("TunnelSubject with empty connID = nil error")
	}
}

func TestValidateTunnelFrame(t *testing.T) {
	if err := eventbus.ValidateTunnelFrame(make([]byte, eventbus.MaxTunnelFrame)); err != nil {
		t.Errorf("frame at bound = %v, want nil", err)
	}
	if err := eventbus.ValidateTunnelFrame(make([]byte, eventbus.MaxTunnelFrame+1)); err == nil {
		t.Error("frame over bound = nil, want error")
	}
}

func TestConnectBudgetExhausted(t *testing.T) {
	start := time.Now()
	_, err := eventbus.Connect(context.Background(), "nats://127.0.0.1:1",
		eventbus.WithConnectBudget(150*time.Millisecond))
	if err == nil {
		t.Fatal("Connect to unreachable endpoint = nil error")
	}
	if !strings.Contains(err.Error(), "eventbus: connect") {
		t.Errorf("error = %v, want eventbus: connect prefix", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Connect took %s, want bounded by budget", elapsed)
	}
}
