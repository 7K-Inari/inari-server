//nolint:staticcheck // SA1019: x/net/http2 h2c mirrors production stream serving; net/http Protocols h2c hangs connect bidi streams (see internal/stream)
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/go-chi/chi/v5"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/7K-Inari/inari-api/gen/go/inari/agent/v1/agentv1connect"
	"github.com/7K-Inari/inari-server/internal/agentgateway"
	"github.com/7K-Inari/inari-server/internal/authn"
)

// QA: exercises the chi + connecthttp.Mount wiring exactly as run() builds
// it in main.go (shared rpcMux, per-service chi prefix routes, separate
// authed server), over a real HTTP server.

type stubRegistration struct {
	agentv1connect.UnimplementedRegistrationServiceHandler
}

func (stubRegistration) RegisterCluster(_ context.Context, req *agentv1.RegisterClusterRequest) (*agentv1.RegisterClusterResponse, error) {
	if req.RegistrationToken == "" {
		return nil, connect.Errorf(connect.CodeInvalidArgument, "registration_token required")
	}
	return &agentv1.RegisterClusterResponse{ClusterId: "c-qa"}, nil
}

type stubValidator struct{}

func (stubValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	if raw != "good-token" {
		return nil, errors.New("bad token")
	}
	return &authn.Identity{ClusterID: "c-qa"}, nil
}

func newQARouter() http.Handler {
	agentRPC := connect.NewServer()
	agentv1connect.RegisterRegistrationServiceHandler(agentRPC, stubRegistration{})
	authedAgentRPC := connect.NewServer(agentgateway.AuthInterceptor(stubValidator{}))
	agentv1connect.RegisterEventStreamServiceHandler(authedAgentRPC, agentv1connect.UnimplementedEventStreamServiceHandler{})
	agentv1connect.RegisterAgentCredentialsServiceHandler(authedAgentRPC, agentv1connect.UnimplementedAgentCredentialsServiceHandler{})

	rpcMux := http.NewServeMux()
	connecthttp.Mount(rpcMux, agentRPC)
	connecthttp.Mount(rpcMux, authedAgentRPC)

	router := chi.NewRouter()
	router.Handle("/"+agentv1connect.RegistrationServiceName+"/*", rpcMux)
	router.Handle("/"+agentv1connect.EventStreamServiceName+"/*", rpcMux)
	router.Handle("/"+agentv1connect.AgentCredentialsServiceName+"/*", rpcMux)
	return router
}

func TestQARoutingUnaryThroughChi(t *testing.T) {
	srv := httptest.NewServer(newQARouter())
	t.Cleanup(srv.Close)

	client := agentv1connect.NewRegistrationServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL, connecthttp.WithReadMaxBytes(0))))
	resp, err := client.RegisterCluster(context.Background(), &agentv1.RegisterClusterRequest{RegistrationToken: "tok"})
	if err != nil {
		t.Fatalf("unary call through chi mount: %v", err)
	}
	if resp.ClusterId != "c-qa" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestQARoutingAuthInterceptorFiresThroughChi(t *testing.T) {
	// Bidi streaming requires HTTP/2; serve h2c and dial with an h2c client.
	srv := httptest.NewUnstartedServer(h2c.NewHandler(newQARouter(), &http2.Server{}))
	srv.Start()
	t.Cleanup(srv.Close)
	h2client := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}

	client := agentv1connect.NewEventStreamServiceClient(
		connect.NewClient(connecthttp.NewTransport(h2client, srv.URL, connecthttp.WithReadMaxBytes(0))))

	// No token: the server interceptor must reject before the handler runs.
	stream, err := client.Connect(context.Background())
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer func() { _ = stream.Close() }()
	if err := stream.Send(&agentv1.ConnectRequest{}); err != nil {
		t.Fatalf("send: %v", err)
	}
	_, err = stream.Receive()
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodeUnauthenticated {
		t.Fatalf("expected unauthenticated, got %v", err)
	}

	// Valid token: the interceptor passes and the unimplemented handler
	// answers — proving identity flows through the mounted chain.
	ctx, info := connect.NewClientContext(context.Background())
	info.RequestHeader().Set("Authorization", "Bearer good-token")
	authed, err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("open authed stream: %v", err)
	}
	defer func() { _ = authed.Close() }()
	_ = authed.Send(&agentv1.ConnectRequest{})
	_, err = authed.Receive()
	var authErr *connect.Error
	if !errors.As(err, &authErr) || authErr.Code() != connect.CodeUnimplemented {
		t.Fatalf("expected unimplemented past the interceptor, got %v", err)
	}
}

func TestQARoutingUnknownMethodIsUnimplementedNotChi404(t *testing.T) {
	srv := httptest.NewServer(newQARouter())
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost,
		srv.URL+"/"+agentv1connect.RegistrationServiceName+"/NoSuchMethod",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	if strings.Contains(string(body), "404 page not found") {
		t.Fatalf("chi 404 leaked for unknown procedure: %s", body)
	}
	if !strings.Contains(string(body), "unimplemented") && res.StatusCode == http.StatusNotFound {
		t.Fatalf("expected connect unimplemented response, got %d %s", res.StatusCode, body)
	}
}

func TestQARoutingUnrelatedPathStillChi404(t *testing.T) {
	srv := httptest.NewServer(newQARouter())
	t.Cleanup(srv.Close)

	res, err := srv.Client().Get(srv.URL + "/definitely/not/here")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for unrelated path, got %d", res.StatusCode)
	}
}

// TestQAWireCompatRawJSON posts the exact bytes a v1 (or TS) Connect client
// sends — Connect-protocol unary JSON — proving wire compatibility with the
// v2 server independent of the Go client version.
func TestQAWireCompatRawJSON(t *testing.T) {
	srv := httptest.NewServer(newQARouter())
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost,
		srv.URL+"/"+agentv1connect.RegistrationServiceName+"/RegisterCluster",
		strings.NewReader(`{"registrationToken":"tok"}`))
	req.Header.Set("Content-Type", "application/json")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("raw JSON unary call failed: %d %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), `"clusterId":"c-qa"`) {
		t.Fatalf("unexpected wire response: %s", body)
	}
}
