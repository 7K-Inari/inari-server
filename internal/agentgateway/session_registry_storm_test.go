package agentgateway

import (
	"sync"
	"sync/atomic"
	"testing"
)

// QA adversarial: concurrent registration storm on one cluster must leave
// exactly one current session, never panic on double-close, and cancel each
// evicted session exactly once.
func TestRegisterSessionStorm(t *testing.T) {
	gw := &Gateway{}
	const n = 200
	var cancels atomic.Int64
	var wg sync.WaitGroup
	handles := make(chan *sessionHandle, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := gw.registerSession("cluster:hot", func() { cancels.Add(1) })
			handles <- h
		}()
	}
	wg.Wait()
	close(handles)

	// Exactly one handle is current; all others must have been evicted.
	var hs []*sessionHandle
	for h := range handles {
		hs = append(hs, h)
	}
	gw.sessionsMu.Lock()
	current := gw.sessions["cluster:hot"]
	gw.sessionsMu.Unlock()
	if current == nil {
		t.Fatal("no current session after storm")
	}
	evicted := 0
	for _, h := range hs {
		if h == current {
			continue
		}
		select {
		case <-h.done:
			evicted++
		default:
			t.Fatalf("non-current session %s was never evicted", h.id)
		}
	}
	if evicted != n-1 {
		t.Fatalf("want %d evicted, got %d", n-1, evicted)
	}
	if got := cancels.Load(); got != n-1 {
		t.Fatalf("want %d cancels, got %d", n-1, got)
	}

	// Late unregisters of every evicted handle must not remove the winner.
	for _, h := range hs {
		if h != current {
			gw.unregisterSession("cluster:hot", h)
		}
	}
	gw.sessionsMu.Lock()
	if gw.sessions["cluster:hot"] != current {
		t.Fatal("late unregister clobbered the current session")
	}
	gw.sessionsMu.Unlock()
}
