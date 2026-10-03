package kubeproxy

import (
	"context"
	"testing"

	tunnelv1 "github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v1"
)

func TestSessionRegistryLastWriterWins(t *testing.T) {
	r := NewSessionRegistry()
	s1 := newSession(context.Background(), "c1", func(*tunnelv1.TunnelMessage) error { return nil }, 0)
	if ev := r.Register(s1); ev != nil {
		t.Fatalf("first register evicted %v", ev)
	}
	s2 := newSession(context.Background(), "c1", func(*tunnelv1.TunnelMessage) error { return nil }, 0)
	if ev := r.Register(s2); ev != s1 {
		t.Fatalf("second register evicted %v, want s1", ev)
	}
	select {
	case <-s1.done:
	default:
		t.Fatal("evicted session not closed")
	}
	if got := r.Get("c1"); got != s2 {
		t.Fatalf("Get = %v, want s2", got)
	}
	// Late unregister of the evicted session must not clobber s2.
	r.Unregister(s1)
	if got := r.Get("c1"); got != s2 {
		t.Fatal("stale unregister clobbered the replacement session")
	}
	r.Unregister(s2)
	if got := r.Get("c1"); got != nil {
		t.Fatalf("Get after unregister = %v", got)
	}
}

func TestSessionRegistryCloseAll(t *testing.T) {
	r := NewSessionRegistry()
	s1 := newSession(context.Background(), "c1", func(*tunnelv1.TunnelMessage) error { return nil }, 0)
	s2 := newSession(context.Background(), "c2", func(*tunnelv1.TunnelMessage) error { return nil }, 0)
	r.Register(s1)
	r.Register(s2)
	r.CloseAll("shutdown")
	for _, s := range []*Session{s1, s2} {
		select {
		case <-s.done:
		default:
			t.Fatalf("session %s not closed", s.id)
		}
	}
	if r.Get("c1") != nil || r.Get("c2") != nil {
		t.Fatal("registry not emptied")
	}
}

func TestSessionSendAfterClose(t *testing.T) {
	s := newSession(context.Background(), "c1", func(*tunnelv1.TunnelMessage) error { return nil }, 0)
	s.close("test")
	if err := s.Send(&tunnelv1.TunnelMessage{}); err == nil {
		t.Fatal("send on closed session succeeded")
	}
}

func TestSessionCloseClosesConns(t *testing.T) {
	s := newSession(context.Background(), "c1", func(*tunnelv1.TunnelMessage) error { return nil }, 0)
	c := s.mux.alloc("conn1")
	s.close("test")
	select {
	case <-c.closed:
	default:
		t.Fatal("session close did not close its conns")
	}
}
