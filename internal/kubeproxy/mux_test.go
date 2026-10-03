package kubeproxy

import (
	"fmt"
	"testing"

	tunnelv1 "github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v1"
)

func frameMsg(connID string, n int) *tunnelv1.TunnelMessage {
	return &tunnelv1.TunnelMessage{
		ConnectionId: connID,
		Payload: &tunnelv1.TunnelMessage_Frame{Frame: &tunnelv1.TunnelFrame{
			Data: make([]byte, n),
		}},
	}
}

func TestMuxRouteFrame(t *testing.T) {
	m := newConnMux("c1", 0)
	c := m.alloc("conn1")
	m.route(frameMsg("conn1", 100))
	select {
	case msg := <-c.fromAgent:
		if msg.GetFrame() == nil {
			t.Fatal("routed message is not a frame")
		}
	default:
		t.Fatal("frame not routed")
	}
	if c.bytesOut.Load() != 100 {
		t.Fatalf("bytesOut = %d", c.bytesOut.Load())
	}
}

func TestMuxByteCapExceeded(t *testing.T) {
	m := newConnMux("c1", 150)
	c := m.alloc("conn1")
	m.route(frameMsg("conn1", 100))
	m.route(frameMsg("conn1", 100)) // 200 > 150
	select {
	case <-c.closed:
	default:
		t.Fatal("conn not closed on byte-cap exceed")
	}
	if c.CloseReason() != CloseReasonByteCapExceeded {
		t.Fatalf("reason = %q", c.CloseReason())
	}
	// The exceeding frame must not be delivered.
	if len(c.fromAgent) != 1 {
		t.Fatalf("delivered frames = %d, want 1", len(c.fromAgent))
	}
}

func TestMuxCountInCap(t *testing.T) {
	m := newConnMux("c1", 10)
	c := m.alloc("conn1")
	if !m.countIn(c, 10) {
		t.Fatal("countIn at cap rejected")
	}
	if m.countIn(c, 1) {
		t.Fatal("countIn beyond cap accepted")
	}
}

func TestMuxBackpressureClosesConn(t *testing.T) {
	m := newConnMux("c1", 0)
	c := m.alloc("conn1")
	for i := 0; i < connChanBounds; i++ {
		m.route(frameMsg("conn1", 1))
	}
	select {
	case <-c.closed:
		t.Fatal("conn closed before the channel filled")
	default:
	}
	m.route(frameMsg("conn1", 1)) // one past the bound
	select {
	case <-c.closed:
	default:
		t.Fatal("conn not closed on backpressure")
	}
	if c.CloseReason() != CloseReasonBackpressure {
		t.Fatalf("reason = %q", c.CloseReason())
	}
}

func TestMuxRouteClose(t *testing.T) {
	m := newConnMux("c1", 0)
	c := m.alloc("conn1")
	m.route(&tunnelv1.TunnelMessage{
		ConnectionId: "conn1",
		Payload:      &tunnelv1.TunnelMessage_Close{Close: &tunnelv1.TunnelClose{Reason: "remote"}},
	})
	select {
	case <-c.closed:
	default:
		t.Fatal("close not routed")
	}
	if c.CloseReason() != "remote" {
		t.Fatalf("reason = %q", c.CloseReason())
	}
}

func TestMuxRouteUnknownConnDropped(t *testing.T) {
	m := newConnMux("c1", 0)
	m.route(frameMsg("ghost", 1)) // must not panic
}

func TestMuxCloseAll(t *testing.T) {
	m := newConnMux("c1", 0)
	var conns []*proxyConn
	for i := 0; i < 3; i++ {
		conns = append(conns, m.alloc(fmt.Sprint(i)))
	}
	m.closeAll("bye")
	for _, c := range conns {
		select {
		case <-c.closed:
		default:
			t.Fatalf("conn %s not closed", c.id)
		}
	}
}
