package kubeproxy

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	tunnelv2 "github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v2"
)

// flipFlags is a dynamic FlagEvaluator for watcher tests.
type flipFlags struct {
	platform atomic.Bool
	disabled map[string]bool
}

func (f *flipFlags) KubectlAccessEnabled(_ context.Context, clusterID string) bool {
	if !f.platform.Load() {
		return false
	}
	return !f.disabled[clusterID]
}

func TestFlagWatcherClusterScopedClose(t *testing.T) {
	flags := &flipFlags{disabled: map[string]bool{}}
	flags.platform.Store(true)
	sessions := NewSessionRegistry()
	keep := newSession(context.Background(), "clu-keep", func(*tunnelv2.TunnelMessage) error { return nil }, 0)
	drop := newSession(context.Background(), "clu-drop", func(*tunnelv2.TunnelMessage) error { return nil }, 0)
	sessions.Register(keep)
	sessions.Register(drop)

	flags.disabled["clu-drop"] = true
	w := NewFlagWatcher(flags, sessions)
	w.tick(context.Background())

	if sessions.Get("clu-drop") != nil {
		t.Error("disabled cluster session still registered")
	}
	if sessions.Get("clu-keep") == nil {
		t.Error("unaffected cluster session was closed")
	}

	// Re-enable: no further action; the agent reconnects on its own.
	flags.disabled["clu-drop"] = false
	w.tick(context.Background())
	if sessions.Get("clu-keep") == nil {
		t.Error("re-enable must not close healthy sessions")
	}
}

func TestFlagWatcherPlatformCloseAll(t *testing.T) {
	flags := &flipFlags{disabled: map[string]bool{}}
	flags.platform.Store(true)
	sessions := NewSessionRegistry()
	s1 := newSession(context.Background(), "clu-1", func(*tunnelv2.TunnelMessage) error { return nil }, 0)
	s2 := newSession(context.Background(), "clu-2", func(*tunnelv2.TunnelMessage) error { return nil }, 0)
	sessions.Register(s1)
	sessions.Register(s2)

	flags.platform.Store(false)
	w := NewFlagWatcher(flags, sessions)
	w.tick(context.Background())
	if got := sessions.Clusters(); len(got) != 0 {
		t.Errorf("platform disable must close all sessions, left %v", got)
	}
}

func TestFlagWatcherRunStopsOnCancel(t *testing.T) {
	flags := &flipFlags{disabled: map[string]bool{}}
	flags.platform.Store(true)
	w := NewFlagWatcher(flags, NewSessionRegistry())
	w.Interval = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
}
