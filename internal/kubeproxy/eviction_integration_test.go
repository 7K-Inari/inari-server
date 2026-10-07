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

	tunnelv2 "github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v2"
	"github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v2/tunnelv2connect"
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

	// Clean disconnect of the replacement (no successor) removes the row.
	agent1.close()
	agent2.close()
	deadline = time.Now().Add(5 * time.Second)
	for {
		ok, err = NewLivenessReader(database.Pool, 0).Available(context.Background(), "c1")
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("heartbeat row survived a clean disconnect with no replacement session")
		}
		time.Sleep(25 * time.Millisecond)
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
	client := tunnelv2connect.NewTunnelServiceClient(h2cClient, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream := client.Connect(ctx)
	stream.RequestHeader().Set("Authorization", "Bearer agent-c1")
	if err := stream.Send(&tunnelv2.TunnelMessage{
		Payload: &tunnelv2.TunnelMessage_Ping{Ping: &tunnelv2.TunnelPing{}},
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
