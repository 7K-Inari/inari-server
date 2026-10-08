package kubeproxy

import (
	"context"
	"log/slog"
	"sync"

	tunnelv2 "github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v2"
	"github.com/google/uuid"
)

// Session is one live tunnel-agent stream for a cluster. It owns the connID
// mux and a serialized send path onto the stream. In-memory only — kubeproxy
// is otherwise stateless.
type Session struct {
	id        string
	clusterID string

	ctx    context.Context
	cancel context.CancelFunc
	// done is closed when the session is evicted or torn down (mirrors
	// agentgateway's sessionHandle).
	done chan struct{}

	sendMu sync.Mutex
	sendFn func(*tunnelv2.TunnelMessage) error

	mux *connMux
}

// newSession derives the session context from parent (the stream handler's
// context): eviction via close() cancels it, unblocking stream.Receive.
func newSession(parent context.Context, clusterID string, sendFn func(*tunnelv2.TunnelMessage) error, byteCap int64) *Session {
	ctx, cancel := context.WithCancel(parent)
	return &Session{
		id:        uuid.NewString(),
		clusterID: clusterID,
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		sendFn:    sendFn,
		mux:       newConnMux(clusterID, byteCap),
	}
}

// Send serializes stream writes (proxy handlers on many conns plus the
// stream loop may all send). Sends on a dead session fail fast.
func (s *Session) Send(msg *tunnelv2.TunnelMessage) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	default:
	}
	return s.sendFn(msg)
}

// close terminates the session: cancels its context (the stream loop
// returns), closes every proxied conn, and closes done. Idempotent.
func (s *Session) close(reason string) {
	s.cancel()
	s.mux.closeAll(reason)
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

// drain blocks until in-flight Sends complete. Call it after close(): the
// cancelled context makes any later Send bail at the ctx check, so once
// drain returns no goroutine will enter sendFn again — the stream's
// end-of-stream write (connect handler Close) cannot race a proxied send.
func (s *Session) drain() {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	_ = s.ctx.Err() // non-empty critical section; close() ran first
}

// SessionRegistry fences tunnel sessions per cluster_id, last-writer-wins
// (mirrors agentgateway/session_registry.go): a reconnecting tunnel agent
// deterministically evicts its stale predecessor.
type SessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

// NewSessionRegistry builds an empty registry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{sessions: map[string]*Session{}}
}

// Register records sess as the live session for its cluster, evicting any
// previous one. Returns the evicted session (nil when none).
func (r *SessionRegistry) Register(sess *Session) (evicted *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old := r.sessions[sess.clusterID]; old != nil {
		slog.Warn("kubeproxy: evicting stale tunnel session (duplicate stream for cluster)",
			"cluster", sess.clusterID, "evicted_session", old.id, "new_session", sess.id)
		evicted = old
	}
	r.sessions[sess.clusterID] = sess
	if evicted != nil {
		// Close outside the lock path is unnecessary (close never blocks on
		// the registry), but keep eviction atomic with registration.
		evicted.close("evicted by reconnect")
	}
	return evicted
}

// Get returns the live session for clusterID, or nil.
func (r *SessionRegistry) Get(clusterID string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[clusterID]
}

// Unregister removes sess only if it is still the current session — an
// evicted session's late unregister must never clobber its replacement.
func (r *SessionRegistry) Unregister(sess *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[sess.clusterID] == sess {
		delete(r.sessions, sess.clusterID)
	}
}

// CloseAll terminates every session (shutdown, or a platform-scoped flag
// flip to off).
func (r *SessionRegistry) CloseAll(reason string) {
	r.mu.Lock()
	sessions := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.sessions = map[string]*Session{}
	r.mu.Unlock()
	for _, s := range sessions {
		s.close(reason)
	}
}

// Clusters returns the cluster IDs with a live session (FlagWatcher polls
// the per-cluster flag for each).
func (r *SessionRegistry) Clusters() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.sessions))
	for id := range r.sessions {
		out = append(out, id)
	}
	return out
}

// CloseCluster terminates the live session of one cluster (cluster-scoped
// flag flip to off). The Connect handler's deferred cleanup unregisters and
// writes the heartbeat disconnect.
func (r *SessionRegistry) CloseCluster(clusterID, reason string) {
	r.mu.Lock()
	sess := r.sessions[clusterID]
	delete(r.sessions, clusterID)
	r.mu.Unlock()
	if sess != nil {
		sess.close(reason)
	}
}
