//go:build integration

package kubeproxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	tunnelv1 "github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v1"
	"github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v1/tunnelv1connect"
)

// TestTunnelEvictionKeepsHeartbeat pins the last-writer-wins reconnect
// behavior: a duplicate Connect for the same cluster evicts the stale
// session, and the evicted session's teardown must NOT delete the
// replacement's heartbeat row (access-info would report a live tunnel as
// unavailable until the next full reconnect).
func TestTunnelEvictionKeepsHeartbeat(t *testing.T) {
	database := setupInfra(t)
	srv, sessions := startProxy(t, database)
	upstream := fakeAPIServer(t, nil)
	defer upstream.Close()

	agent1 := startFakeAgent(t, srv.URL, upstream)
	waitForSession(t, sessions, "c1")
	sess1 := sessions.Get("c1")

	// Agent reconnects (deploy roll, network blip): second stream fences
	// the first out.
	agent2 := startFakeAgent(t, srv.URL, upstream)
	deadline := time.Now().Add(10 * time.Second)
	for sessions.Get("c1") == sess1 {
		if time.Now().After(deadline) {
			t.Fatal("stale session never evicted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-sess1.done:
	case <-time.After(5 * time.Second):
		t.Fatal("evicted session was not closed")
	}

	// Let the evicted session's deferred teardown fully settle, then the
	// heartbeat row must still be present and fresh (it belongs to the
	// replacement session now).
	time.Sleep(500 * time.Millisecond)
	ok, err := NewLivenessReader(database.Pool, 0).Available(context.Background(), "c1")
	if err != nil || !ok {
		t.Fatalf("liveness after eviction = %v, %v — evicted session deleted the replacement's heartbeat row", ok, err)
	}

	// Clean disconnect of the replacement (no successor) keeps the row
	// fresh: agents rotate sessions seconds apart, and deleting the row
	// flapped access-info tunnelAvailable=false in the reconnect gap. The
	// row must instead expire via the reader's freshness window.
	agent1.close()
	agent2.close()
	time.Sleep(500 * time.Millisecond) // let teardown settle
	ok, err = NewLivenessReader(database.Pool, 0).Available(context.Background(), "c1")
	if err != nil || !ok {
		t.Fatalf("liveness right after clean disconnect = %v, %v — rotation gaps must stay available", ok, err)
	}
	// With a near-zero freshness window the same row reads as unavailable:
	// true teardown is detected by expiry, not deletion.
	stale, err := NewLivenessReader(database.Pool, 50*time.Millisecond).Available(context.Background(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if stale {
		t.Fatal("stale read: clean-disconnect row must expire via the freshness window")
	}
}

// TestTunnelConnectFlagOffRejected: with kubectl_access.enabled off, new
// tunnel streams are refused with CodeUnavailable.
func TestTunnelConnectFlagOffRejected(t *testing.T) {
	database := setupInfra(t)
	srv, _ := startProxy(t, database, withFlags(StaticFlagEvaluator{Enabled: false}))

	h2cClient := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	client := tunnelv1connect.NewTunnelServiceClient(h2cClient, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream := client.Connect(ctx)
	stream.RequestHeader().Set("Authorization", "Bearer agent-c1")
	if err := stream.Send(&tunnelv1.TunnelMessage{
		Payload: &tunnelv1.TunnelMessage_Ping{Ping: &tunnelv1.TunnelPing{}},
	}); err != nil {
		t.Fatalf("ping: %v", err)
	}
	_, err := stream.Receive()
	if err == nil {
		t.Fatal("tunnel stream accepted with the flag off")
	}
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("code = %v, want unavailable (%v)", connect.CodeOf(err), err)
	}
}
