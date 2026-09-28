package audit

import (
	"context"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestBackoffSchedule(t *testing.T) {
	got := backoffSchedule(50)
	if len(got) != 50 {
		t.Fatalf("len = %d, want 50", len(got))
	}
	want := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("backoff[%d] = %s, want %s", i, got[i], w)
		}
	}
	for i := len(want); i < len(got); i++ {
		if got[i] != 30*time.Second {
			t.Errorf("backoff[%d] = %s, want 30s cap", i, got[i])
		}
	}

	short := backoffSchedule(3)
	if len(short) != 3 || short[0] != time.Second || short[1] != 2*time.Second || short[2] != 5*time.Second {
		t.Errorf("backoffSchedule(3) = %v", short)
	}
}

func TestNamedHandlerHandles(t *testing.T) {
	h := Named("test-handler", HandlerFunc{
		Types: []string{"tenant.created", "team.created"},
		Fn:    func(context.Context, *types.OutboxEvent) error { return nil },
	})
	if !h.handles("tenant.created") || !h.handles("team.created") {
		t.Error("handles = false for registered types")
	}
	if h.handles("tenant.deleted") {
		t.Error("handles = true for unregistered type")
	}
	if h.Name() != "test-handler" {
		t.Errorf("Name() = %q", h.Name())
	}
}

func TestHandlerNameRE(t *testing.T) {
	valid := []string{"authz-tuple-writer", "notifications", "rbac-materialize", "a1"}
	for _, n := range valid {
		if !handlerNameRE.MatchString(n) {
			t.Errorf("handlerNameRE rejected valid name %q", n)
		}
	}
	invalid := []string{"", "-lead", "has_underscore", "has.dot", "Upper", "has space"}
	for _, n := range invalid {
		if handlerNameRE.MatchString(n) {
			t.Errorf("handlerNameRE accepted invalid name %q", n)
		}
	}
}
