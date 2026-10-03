package kubeproxy

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	tunnelv1 "github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v1"

	"github.com/7K-Inari/inari-server/internal/metrics"
)

// connChanBounds caps buffered agent→proxy messages per connection; a slow
// user client must not queue unbounded frames in memory (plan §7 risk 2: no
// windowing in v1 — gRPC flow control plus these bounds).
const connChanBounds = 64

// Close reasons surfaced in TunnelClose and the audit payload.
const (
	CloseReasonDone            = "done"
	CloseReasonByteCapExceeded = "byte_cap_exceeded"
	CloseReasonBackpressure    = "backpressure"
	CloseReasonTunnelClosed    = "tunnel_closed"
	CloseReasonMaxLifetime     = "max_lifetime"
	CloseReasonEvicted         = "evicted by reconnect"
)

// proxyConn is one proxied HTTP request's state on a tunnel session.
type proxyConn struct {
	id        string
	createdAt time.Time

	// fromAgent carries TunnelOpenResult / TunnelFrame / TunnelClose
	// payloads addressed to this connID. Bounded; a full channel closes the
	// conn (backpressure) rather than stalling the whole session.
	fromAgent chan *tunnelv1.TunnelMessage

	bytesIn  atomic.Int64 // user → agent
	bytesOut atomic.Int64 // agent → user

	closed  chan struct{}
	once    sync.Once
	reasonV atomic.Value // string
}

func (c *proxyConn) close(reason string) {
	c.once.Do(func() {
		c.reasonV.Store(reason)
		close(c.closed)
	})
}

// CloseReason reports why the conn ended ("" while open).
func (c *proxyConn) CloseReason() string {
	if v := c.reasonV.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// connMux routes tunnel messages between the session stream and per-connID
// proxy handlers.
type connMux struct {
	clusterID string
	byteCap   int64 // per-conn total byte cap; 0 = unlimited
	conns     sync.Map
}

func newConnMux(clusterID string, byteCap int64) *connMux {
	return &connMux{clusterID: clusterID, byteCap: byteCap}
}

func (m *connMux) alloc(id string) *proxyConn {
	c := &proxyConn{
		id:        id,
		createdAt: time.Now(),
		fromAgent: make(chan *tunnelv1.TunnelMessage, connChanBounds),
		closed:    make(chan struct{}),
	}
	m.conns.Store(id, c)
	return c
}

func (m *connMux) get(id string) *proxyConn {
	if v, ok := m.conns.Load(id); ok {
		return v.(*proxyConn)
	}
	return nil
}

func (m *connMux) remove(id string) { m.conns.Delete(id) }

// countIn accounts user→agent bytes; returns false when the per-conn byte
// cap is exceeded (the caller closes the conn).
func (m *connMux) countIn(c *proxyConn, n int) bool {
	if m.byteCap <= 0 {
		c.bytesIn.Add(int64(n))
		return true
	}
	return c.bytesIn.Add(int64(n)) <= m.byteCap
}

// route delivers one agent→proxy message to its conn. Called from the
// session's single stream-receive loop — never blocks (a full per-conn
// channel closes that conn instead of stalling siblings).
func (m *connMux) route(msg *tunnelv1.TunnelMessage) {
	c := m.get(msg.GetConnectionId())
	if c == nil {
		return // conn already finished; late frames are dropped
	}
	if f := msg.GetFrame(); f != nil {
		if m.byteCap > 0 && c.bytesOut.Add(int64(len(f.GetData()))) > m.byteCap {
			metrics.RecordKubeproxyConn(context.Background(), metrics.KubeproxyByteCapExceeded)
			c.close(CloseReasonByteCapExceeded)
			return
		}
		if m.byteCap <= 0 {
			c.bytesOut.Add(int64(len(f.GetData())))
		}
	}
	if msg.GetClose() != nil {
		c.close(msg.GetClose().GetReason())
		return
	}
	select {
	case c.fromAgent <- msg:
	default:
		// Slow user client: close this conn rather than blocking the
		// session's receive loop (head-of-line protection).
		c.close(CloseReasonBackpressure)
	}
}

// closeAll terminates every conn (session teardown / shutdown).
func (m *connMux) closeAll(reason string) {
	m.conns.Range(func(_, v any) bool {
		v.(*proxyConn).close(reason)
		return true
	})
}
