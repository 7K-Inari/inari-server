package agentgateway

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestRegisterSessionEvictsPrevious(t *testing.T) {
	gw := &Gateway{}
	var evicted atomic.Bool
	h1 := gw.registerSession("cluster:a", func() { evicted.Store(true) })
	if h1 == nil || h1.id == "" {
		t.Fatal("registerSession must return a handle with an id")
	}
	select {
	case <-h1.done:
		t.Fatal("freshly registered session already done")
	default:
	}

	h2 := gw.registerSession("cluster:a", func() {})
	if h2.id == h1.id {
		t.Fatal("each session must get a distinct id")
	}
	// Last-writer-wins: the first session is cancelled...
	select {
	case <-h1.done:
	case <-time.After(2 * time.Second):
		t.Fatal("stale session was not evicted")
	}
	if !evicted.Load() {
		t.Fatal("evicted session's cancel was not called")
	}
	// ...and the registry now holds the second.
	gw.sessionsMu.Lock()
	current := gw.sessions["cluster:a"]
	gw.sessionsMu.Unlock()
	if current != h2 {
		t.Fatal("registry must hold the newest session")
	}
}

func TestRegisterSessionDifferentClustersCoexist(t *testing.T) {
	gw := &Gateway{}
	var evicted atomic.Bool
	gw.registerSession("cluster:a", func() { evicted.Store(true) })
	gw.registerSession("cluster:b", func() {})
	if evicted.Load() {
		t.Fatal("unrelated cluster session must not be evicted")
	}
	gw.sessionsMu.Lock()
	n := len(gw.sessions)
	gw.sessionsMu.Unlock()
	if n != 2 {
		t.Fatalf("want 2 live sessions, got %d", n)
	}
}

func TestUnregisterCurrentSession(t *testing.T) {
	gw := &Gateway{}
	h := gw.registerSession("cluster:a", func() {})
	gw.unregisterSession("cluster:a", h)
	gw.sessionsMu.Lock()
	_, ok := gw.sessions["cluster:a"]
	gw.sessionsMu.Unlock()
	if ok {
		t.Fatal("current session must be removed on unregister")
	}
}

func TestUnregisterStaleHandleKeepsCurrent(t *testing.T) {
	gw := &Gateway{}
	h1 := gw.registerSession("cluster:a", func() {})
	h2 := gw.registerSession("cluster:a", func() {})
	// h1 was evicted by h2; its late unregister must not clobber h2.
	gw.unregisterSession("cluster:a", h1)
	gw.sessionsMu.Lock()
	current := gw.sessions["cluster:a"]
	gw.sessionsMu.Unlock()
	if current != h2 {
		t.Fatal("stale unregister must not remove the current session")
	}
}

// blockingStream is a streamConn whose Receive blocks until closed.
type blockingStream struct{ closed chan struct{} }

func (s *blockingStream) Receive() (*agentv1.ConnectRequest, error) {
	<-s.closed
	return nil, io.EOF
}

func (s *blockingStream) Send(*agentv1.ConnectResponse) error { return nil }

func TestEvictedSessionRunReturns(t *testing.T) {
	cfg := (&Config{}).withDefaults()
	gw := &Gateway{cfg: cfg, queue: &fakeQueue{}}
	stream := &blockingStream{closed: make(chan struct{})}
	defer close(stream.closed)

	sctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := gw.registerSession("cluster:a", cancel)

	done := make(chan error, 1)
	go func() {
		done <- gw.newSession(&types.Cluster{ID: "cluster:a", OrgID: "org:test"}).run(sctx, stream)
	}()
	_ = h

	// A newer stream for the same cluster evicts this session.
	gw.registerSession("cluster:a", func() {})
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("evicted session run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("evicted session did not stop promptly")
	}
}
