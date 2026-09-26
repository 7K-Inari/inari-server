package agentgateway

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

// sessionHandle tracks the one live bidi session per cluster identity.
// Fencing is last-writer-wins: a new stream for an already-connected
// cluster deterministically evicts the stale session (ADR: inari-agent
// active-passive failover must not depend on races).
type sessionHandle struct {
	id     string
	cancel context.CancelFunc
	done   chan struct{} // closed when evicted
}

// registerSession records a new session for clusterID, evicting (cancelling)
// any previous one. The caller wires its session context's cancel func.
func (g *Gateway) registerSession(clusterID string, cancel context.CancelFunc) *sessionHandle {
	h := &sessionHandle{id: uuid.NewString(), cancel: cancel, done: make(chan struct{})}
	g.sessionsMu.Lock()
	defer g.sessionsMu.Unlock()
	if g.sessions == nil {
		g.sessions = map[string]*sessionHandle{}
	}
	if old := g.sessions[clusterID]; old != nil {
		slog.Warn("agentgateway: evicting stale session (duplicate stream for cluster)",
			"cluster", clusterID, "evicted_session", old.id, "new_session", h.id)
		close(old.done)
		old.cancel()
	}
	g.sessions[clusterID] = h
	return h
}

// unregisterSession removes h only if it is still the current session — an
// evicted session's late unregister must never clobber its replacement.
func (g *Gateway) unregisterSession(clusterID string, h *sessionHandle) {
	g.sessionsMu.Lock()
	defer g.sessionsMu.Unlock()
	if g.sessions[clusterID] == h {
		delete(g.sessions, clusterID)
	}
}
