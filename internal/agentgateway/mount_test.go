package agentgateway

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	connect "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/types/known/anypb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/7K-Inari/inari-api/gen/go/inari/agent/v1/agentv1connect"
)

// readAllStream is a stub EventStreamService that reads the client stream
// to completion — it exists to exercise the transport's per-message read
// limit without the gateway's auth/registry dependencies.
type readAllStream struct{ t *testing.T }

// Connect reads exactly one message and answers with one small frame — the
// test asserts on whether the first read survived the transport's
// per-message read limit, so no half-close semantics are needed.
func (s readAllStream) Connect(_ context.Context, stream agentv1connect.EventStreamServiceConnectServerStream) error {
	msg, err := stream.Receive()
	if err != nil {
		s.t.Logf("stub: receive error: %v", err)
		return err
	}
	s.t.Logf("stub: received event %s", msg.Event.GetEventId())
	pong, _ := anypb.New(&agentv1.Ping{})
	return stream.Send(&agentv1.ConnectResponse{Event: &agentv1.Event{
		EventId: "bye",
		Type:    agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_PING),
		Payload: pong,
	}})
}

// bigHandshake returns a ConnectRequest whose envelope exceeds connect's
// default 4MiB per-message read limit (padded AgentVersion).
func bigHandshake(t *testing.T) *agentv1.ConnectRequest {
	t.Helper()
	any, err := anypb.New(&agentv1.HandshakeRequest{
		AgentVersion:    strings.Repeat("x", 5<<20), // 5MiB
		TenantId:        "org:test",
		ContractVersion: "inari.agent.v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.ConnectRequest{Event: &agentv1.Event{
		EventId: "e1",
		Type:    "inari.agent.handshake.v1",
		Payload: any,
	}}
}

// mountStub wires the stub stream the way cmd/inari-server mounts the real
// gateway: same server constructor, same options list. Bidi streaming
// requires HTTP/2 — h2c via x/net/http2 (the in-cluster path is plaintext
// h2c behind the service mesh boundary too).
func mountStub(t *testing.T, opts ...connecthttp.Option) *httptest.Server {
	t.Helper()
	srv := connect.NewServer()
	agentv1connect.RegisterEventStreamServiceHandler(srv, readAllStream{t})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, srv, opts...)
	ts := httptest.NewUnstartedServer(h2c.NewHandler(mux, &http2.Server{}))
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}

func streamClient(ts *httptest.Server) agentv1connect.EventStreamServiceClient {
	// h2c client (bidi streaming requires HTTP/2): prior-knowledge h2 over
	// plaintext, mirroring the in-cluster agent→server path.
	h2cClient := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	return agentv1connect.NewEventStreamServiceClient(
		connect.NewClient(connecthttp.NewTransport(h2cClient, ts.URL, connecthttp.WithReadMaxBytes(0))))
}

// TestStreamDefaultReadLimitRejectsOversize pins the regression: without
// MountOptions, connect's 4MiB default rejects capability full-syncs from
// CRD-rich clusters (Crossplane/ESO/CNPG schemas alone exceed it), cycling
// the agent's event stream and blinding status streaming.
func TestStreamDefaultReadLimitRejectsOversize(t *testing.T) {
	ts := mountStub(t) // no options: connect default (4MiB)
	stream, err := streamClient(ts).Connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := stream.Send(bigHandshake(t)); err != nil {
		t.Fatalf("send: %v", err)
	}
	_, err = stream.Receive()
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("want resource_exhausted at the default limit, got %v", err)
	}
}

// TestStreamReadLimitAdmitsLargeMessages is the fix assertion: the
// production mount options must admit messages beyond the 4MiB default.
func TestStreamReadLimitAdmitsLargeMessages(t *testing.T) {
	cfg := (&Config{}).withDefaults()
	ts := mountStub(t, cfg.MountOptions()...)
	stream, err := streamClient(ts).Connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := stream.Send(bigHandshake(t)); err != nil {
		t.Fatalf("send: %v", err)
	}
	resp, err := stream.Receive()
	if err != nil {
		t.Fatalf("oversize message must be admitted with MountOptions, got %v", err)
	}
	if resp.Event.GetEventId() != "bye" {
		t.Fatalf("want the stub's pong, got %+v", resp.Event)
	}
}

func TestStreamMaxRecvBytesDefault(t *testing.T) {
	cfg := (&Config{}).withDefaults()
	if cfg.StreamMaxRecvBytes != DefaultStreamMaxRecvBytes {
		t.Fatalf("StreamMaxRecvBytes = %d, want %d", cfg.StreamMaxRecvBytes, DefaultStreamMaxRecvBytes)
	}
}

// TestStreamReadLimitRawConfigLiteral pins the production call pattern:
// cmd/inari-server calls MountOptions on the RAW (pre-withDefaults) Config
// literal, so a zero StreamMaxRecvBytes must self-default at the transport
// (not just inside withDefaults).
func TestStreamReadLimitRawConfigLiteral(t *testing.T) {
	ts := mountStub(t, Config{}.MountOptions()...)
	stream, err := streamClient(ts).Connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := stream.Send(bigHandshake(t)); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := stream.Receive(); err != nil {
		t.Fatalf("raw Config{}.MountOptions() must admit oversize messages, got %v", err)
	}
}

