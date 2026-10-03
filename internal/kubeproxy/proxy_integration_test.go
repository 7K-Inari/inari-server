//go:build integration

package kubeproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	tunnelv1 "github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v1"
	"github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v1/tunnelv1connect"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

// --- fakes -----------------------------------------------------------------

// itUserValidator maps "good" to an acme member with team groups.
type itUserValidator struct{}

func (itUserValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	if raw == "good" {
		return &authn.Identity{
			Subject: "user-1", Email: "dev@acme.example",
			Organizations: []string{"acme"},
			Groups:        []string{"/tenant-acme/devs", "/tenant-other/admins"},
		}, nil
	}
	return nil, errors.New("invalid token")
}

type itAllowAll struct{}

func (itAllowAll) Check(context.Context, string, string, string) (bool, error) { return true, nil }

type itDenyAll struct{}

func (itDenyAll) Check(context.Context, string, string, string) (bool, error) { return false, nil }

type itAgentValidator struct{}

func (itAgentValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	if raw == "agent-c1" {
		return &authn.Identity{ClusterID: "c1", AuthorizedParty: "tunnel-c1"}, nil
	}
	return nil, errors.New("invalid agent token")
}

// tapPipe routes user→agent frames of one conn to its relay goroutine and
// signals conn teardown (TunnelClose) on a separate channel so relays can
// unwind without send-on-closed races.
type tapPipe struct {
	frames chan *tunnelv1.TunnelFrame
	closed chan struct{}
	once   sync.Once
}

func newTapPipe() *tapPipe {
	return &tapPipe{frames: make(chan *tunnelv1.TunnelFrame, 64), closed: make(chan struct{})}
}

func (p *tapPipe) close() { p.once.Do(func() { close(p.closed) }) }

// fakeAgent is the Phase-3 tunnel-agent stand-in: it dials kubeproxy's
// TunnelService as cluster c1 and relays TunnelOpen requests to the fake
// apiserver, streaming frames in both directions.
type fakeAgent struct {
	upstream *httptest.Server
	stream   *connect.BidiStreamForClient[tunnelv1.TunnelMessage, tunnelv1.TunnelMessage]

	mu      sync.Mutex
	sendMu  sync.Mutex // Connect streams are not safe for concurrent Send
	taps    map[string]*tapPipe
	wg      sync.WaitGroup
	closed  atomic.Bool
	errOnce sync.Once
	recvErr error
}

func startFakeAgent(t *testing.T, proxyURL string, upstream *httptest.Server) *fakeAgent {
	t.Helper()
	h2cClient := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	client := tunnelv1connect.NewTunnelServiceClient(h2cClient, proxyURL)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	stream := client.Connect(ctx)
	stream.RequestHeader().Set("Authorization", "Bearer agent-c1")
	a := &fakeAgent{upstream: upstream, stream: stream, taps: map[string]*tapPipe{}}
	// Connect bidi streams initiate the HTTP request lazily on first Send —
	// kick it off with a ping (the real agent heartbeats anyway).
	if err := stream.Send(&tunnelv1.TunnelMessage{
		Payload: &tunnelv1.TunnelMessage_Ping{Ping: &tunnelv1.TunnelPing{}},
	}); err != nil {
		t.Fatalf("agent ping: %v", err)
	}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.serve()
	}()
	t.Cleanup(func() {
		if a.recvErr != nil {
			t.Logf("fake agent receive error: %v", a.recvErr)
		}
	})
	return a
}

func (a *fakeAgent) serve() {
	for {
		msg, err := a.stream.Receive()
		if err != nil {
			if !a.closed.Load() && !errors.Is(err, io.EOF) &&
				!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				a.errOnce.Do(func() { a.recvErr = err })
			}
			return
		}
		switch {
		case msg.GetOpen() != nil:
			tap := newTapPipe()
			a.mu.Lock()
			a.taps[msg.GetConnectionId()] = tap
			a.mu.Unlock()
			a.wg.Add(1)
			go func() {
				defer a.wg.Done()
				a.relay(msg.GetConnectionId(), msg.GetOpen(), tap)
			}()
		case msg.GetClose() != nil:
			a.mu.Lock()
			tap := a.taps[msg.GetConnectionId()]
			delete(a.taps, msg.GetConnectionId())
			a.mu.Unlock()
			if tap != nil {
				tap.close()
			}
		case msg.GetFrame() != nil:
			a.mu.Lock()
			if tap := a.taps[msg.GetConnectionId()]; tap != nil {
				select {
				case tap.frames <- msg.GetFrame():
				default: // test harness: drop rather than block the stream
				}
			}
			a.mu.Unlock()
		}
	}
}

func (a *fakeAgent) send(msg *tunnelv1.TunnelMessage) {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	_ = a.stream.Send(msg)
}

// bodyReader turns tap frames into an io.Reader (ends at half-close or conn
// teardown).
type bodyReader struct{ tap *tapPipe }

func (b bodyReader) Read(p []byte) (int, error) {
	select {
	case f := <-b.tap.frames:
		if f.GetHalfClose() && len(f.GetData()) == 0 {
			return 0, io.EOF
		}
		return copy(p, f.GetData()), nil
	case <-b.tap.closed:
		return 0, io.EOF
	}
}

func (a *fakeAgent) relay(connID string, open *tunnelv1.TunnelOpen, tap *tapPipe) {
	// Mirror the real agent: the conn's terminal message comes from the
	// side that talks to the apiserver.
	defer a.send(&tunnelv1.TunnelMessage{ConnectionId: connID, Payload: &tunnelv1.TunnelMessage_Close{
		Close: &tunnelv1.TunnelClose{Reason: "done"},
	}})
	if open.GetUpgradeExpected() {
		a.relayUpgrade(connID, open, tap)
		return
	}
	url := a.upstream.URL + open.GetPath()
	req, err := http.NewRequest(open.GetMethod(), url, bodyReader{tap})
	if err != nil {
		a.send(&tunnelv1.TunnelMessage{ConnectionId: connID, Payload: &tunnelv1.TunnelMessage_OpenResult{
			OpenResult: &tunnelv1.TunnelOpenResult{Error: err.Error()},
		}})
		return
	}
	for k, v := range open.GetHeaders() {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.send(&tunnelv1.TunnelMessage{ConnectionId: connID, Payload: &tunnelv1.TunnelMessage_OpenResult{
			OpenResult: &tunnelv1.TunnelOpenResult{Error: err.Error()},
		}})
		return
	}
	defer resp.Body.Close()
	hdr := map[string]string{}
	for k, vs := range resp.Header {
		hdr[k] = strings.Join(vs, ", ")
	}
	a.send(&tunnelv1.TunnelMessage{ConnectionId: connID, Payload: &tunnelv1.TunnelMessage_OpenResult{
		OpenResult: &tunnelv1.TunnelOpenResult{Status: int32(resp.StatusCode), Headers: hdr},
	}})
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		buf := make([]byte, MaxTunnelFrame)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				a.send(&tunnelv1.TunnelMessage{ConnectionId: connID, Payload: &tunnelv1.TunnelMessage_Frame{
					Frame: &tunnelv1.TunnelFrame{Data: buf[:n]},
				}})
			}
			if err != nil {
				a.send(&tunnelv1.TunnelMessage{ConnectionId: connID, Payload: &tunnelv1.TunnelMessage_Frame{
					Frame: &tunnelv1.TunnelFrame{HalfClose: true},
				}})
				return
			}
		}
	}()
	select {
	case <-pumpDone:
	case <-tap.closed: // conn torn down mid-response
	}
	_ = resp.Body.Close() // unblock the pump if we're leaving early
	<-pumpDone
}

// relayUpgrade splices a 101-upgraded raw conn (SPDY/websocket shape).
func (a *fakeAgent) relayUpgrade(connID string, open *tunnelv1.TunnelOpen, tap *tapPipe) {
	addr := strings.TrimPrefix(a.upstream.URL, "http://")
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		a.send(&tunnelv1.TunnelMessage{ConnectionId: connID, Payload: &tunnelv1.TunnelMessage_OpenResult{
			OpenResult: &tunnelv1.TunnelOpenResult{Error: err.Error()},
		}})
		return
	}
	defer raw.Close()
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
		open.GetMethod(), open.GetPath(), addr)
	for k, v := range open.GetHeaders() {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	sb.WriteString("\r\n")
	if _, err := raw.Write([]byte(sb.String())); err != nil {
		return
	}
	br := bufio.NewReader(raw)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		a.send(&tunnelv1.TunnelMessage{ConnectionId: connID, Payload: &tunnelv1.TunnelMessage_OpenResult{
			OpenResult: &tunnelv1.TunnelOpenResult{Error: "upstream refused upgrade: " + strings.TrimSpace(status)},
		}})
		return
	}
	hdr := map[string]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
		k, v, _ := strings.Cut(line, ":")
		hdr[textproto.TrimString(k)] = textproto.TrimString(v)
	}
	a.send(&tunnelv1.TunnelMessage{ConnectionId: connID, Payload: &tunnelv1.TunnelMessage_OpenResult{
		OpenResult: &tunnelv1.TunnelOpenResult{Status: 101, Headers: hdr},
	}})
	// upstream → frames
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, MaxTunnelFrame)
		for {
			n, err := br.Read(buf)
			if n > 0 {
				a.send(&tunnelv1.TunnelMessage{ConnectionId: connID, Payload: &tunnelv1.TunnelMessage_Frame{
					Frame: &tunnelv1.TunnelFrame{Data: buf[:n]},
				}})
			}
			if err != nil {
				a.send(&tunnelv1.TunnelMessage{ConnectionId: connID, Payload: &tunnelv1.TunnelMessage_Frame{
					Frame: &tunnelv1.TunnelFrame{HalfClose: true},
				}})
				return
			}
		}
	}()
	// frames → upstream
loop:
	for {
		select {
		case <-tap.closed:
			break loop
		case f := <-tap.frames:
			if len(f.GetData()) > 0 {
				if _, err := raw.Write(f.GetData()); err != nil {
					break loop
				}
			}
			if f.GetHalfClose() {
				break loop
			}
		}
	}
	_ = raw.Close() // unblock the upstream reader goroutine
	<-done
}

func (a *fakeAgent) close() {
	a.closed.Store(true)
	// Unblock relays deterministically — teardown must not depend on the
	// proxy's close messages winning the race against stream shutdown.
	a.mu.Lock()
	for id, tap := range a.taps {
		delete(a.taps, id)
		tap.close()
	}
	a.mu.Unlock()
	_ = a.stream.CloseRequest()
	_ = a.stream.CloseResponse()
	a.wg.Wait()
}

// --- harness ---------------------------------------------------------------

func setupInfra(t *testing.T) *db.DB {
	t.Helper()
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatalf("testdb: %v", err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO organizations (id, slug, display_name, keycloak_org_id)
		VALUES ('org-acme', 'acme', 'Acme', 'kc-acme')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ('c1', 'org-acme', 'c1')`); err != nil {
		t.Fatal(err)
	}
	return database
}

type proxyOption func(*ProxyConfig, *ServerConfig)

func startProxy(t *testing.T, database *db.DB, opts ...proxyOption) (*httptest.Server, *SessionRegistry) {
	t.Helper()
	sessions := NewSessionRegistry()
	pcfg := ProxyConfig{
		Flags: StaticFlagEvaluator{Enabled: true}, Validator: itUserValidator{}, Authz: itAllowAll{},
		Sessions: sessions, DB: database,
	}
	scfg := ServerConfig{
		Flags: pcfg.Flags, Sessions: sessions,
		Heartbeat: NewHeartbeatWriter(database.Pool, "it"),
		AgentAuth: itAgentValidator{},
	}
	for _, o := range opts {
		o(&pcfg, &scfg)
	}
	pcfg.Sessions = sessions
	scfg.Sessions = sessions
	scfg.Proxy = NewProxyHandler(pcfg)
	router, err := NewServer(scfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h2c.NewHandler(router, &http2.Server{}))
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, sessions
}

func withFlags(f FlagEvaluator) proxyOption {
	return func(p *ProxyConfig, s *ServerConfig) { p.Flags = f; s.Flags = f }
}

func withAuthz(c Checker) proxyOption {
	return func(p *ProxyConfig, _ *ServerConfig) { p.Authz = c }
}

func withMaxLifetime(d time.Duration) proxyOption {
	return func(p *ProxyConfig, _ *ServerConfig) { p.MaxLifetime = d }
}

// waitForSession blocks until the agent's tunnel session is registered
// (the Connect RPC returns client-side before the server registers).
func waitForSession(t *testing.T, sessions *SessionRegistry, clusterID string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for sessions.Get(clusterID) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("tunnel session for %s never registered", clusterID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func outboxEvents(t *testing.T, database *db.DB) []types.OutboxEvent {
	t.Helper()
	rows, err := database.Pool.Query(context.Background(),
		`SELECT event_type, payload FROM outbox ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []types.OutboxEvent
	for rows.Next() {
		var ev types.OutboxEvent
		if err := rows.Scan(&ev.EventType, &ev.Payload); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

// --- tests -----------------------------------------------------------------

// fakeAPIServer records the impersonation headers of the last request and
// answers 200 with a fixed body.
func fakeAPIServer(t *testing.T, sawHeaders chan<- http.Header) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sawHeaders != nil {
			sawHeaders <- r.Header.Clone()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"NamespaceList"}`))
	}))
}

func TestProxyEndToEnd(t *testing.T) {
	database := setupInfra(t)
	srv, sessions := startProxy(t, database)
	saw := make(chan http.Header, 1)
	upstream := fakeAPIServer(t, saw)
	defer upstream.Close()
	agent := startFakeAgent(t, srv.URL, upstream)
	waitForSession(t, sessions, "c1")
	defer agent.close()

	req, _ := http.NewRequest(http.MethodGet,
		srv.URL+"/api/v1/tenants/acme/clusters/c1/proxy/api/v1/namespaces?limit=5", nil)
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("Impersonate-User", "mallory") // must be stripped
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "NamespaceList") {
		t.Fatalf("body = %s", body)
	}

	select {
	case h := <-saw:
		if got := h.Get("Impersonate-User"); got != "dev@acme.example" {
			t.Errorf("Impersonate-User = %q", got)
		}
		groups := h.Values("Impersonate-Group")
		if len(groups) != 1 || groups[0] != "/tenant-acme/devs" {
			t.Errorf("Impersonate-Group = %v (client header must be stripped, tenant groups only)", groups)
		}
		if h.Get("Authorization") != "" {
			t.Error("user token leaked to the cluster")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake apiserver saw no request")
	}

	// Heartbeat row present (access-info liveness source).
	ok, err := NewLivenessReader(database.Pool, 0).Available(context.Background(), "c1")
	if err != nil || !ok {
		t.Fatalf("tunnel liveness = %v, %v", ok, err)
	}

	events := waitOutbox(t, database, 2)
	if events[0].EventType != types.EventClusterKubectlProxyOpen ||
		events[1].EventType != types.EventClusterKubectlProxyClose {
		t.Fatalf("outbox events = %v %v", events[0].EventType, events[1].EventType)
	}
	var closePayload types.KubectlProxyPayload
	if err := json.Unmarshal(events[1].Payload, &closePayload); err != nil {
		t.Fatal(err)
	}
	if closePayload.BytesOut == 0 || closePayload.ConnectionID == "" || closePayload.DurationMs < 0 {
		t.Errorf("close payload incomplete: %+v", closePayload)
	}
}

// waitOutbox polls until n outbox rows exist (the close audit trails the
// client-visible EOF by a few ms on containerized Postgres).
func waitOutbox(t *testing.T, database *db.DB, n int) []types.OutboxEvent {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		events := outboxEvents(t, database)
		if len(events) >= n {
			return events
		}
		if time.Now().After(deadline) {
			t.Fatalf("outbox never reached %d rows; got %v", n, events)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestProxyPOSTBodyStreams(t *testing.T) {
	database := setupInfra(t)
	srv, sessions := startProxy(t, database)
	saw := make(chan http.Header, 1)
	upstream := fakeAPIServer(t, saw)
	defer upstream.Close()
	agent := startFakeAgent(t, srv.URL, upstream)
	waitForSession(t, sessions, "c1")
	defer agent.close()

	payload := strings.Repeat("x", 100000) // spans multiple 32 KiB frames
	req, _ := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/tenants/acme/clusters/c1/proxy/api/v1/namespaces", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer good")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
}

func TestProxyGuards(t *testing.T) {
	database := setupInfra(t)
	srv, _ := startProxy(t, database)

	cases := []struct {
		name   string
		token  string
		path   string
		status int
	}{
		{"no token", "", "/api/v1/tenants/acme/clusters/c1/proxy/api", 401},
		{"bad token", "bad", "/api/v1/tenants/acme/clusters/c1/proxy/api", 401},
		{"org mismatch", "good", "/api/v1/tenants/other/clusters/c1/proxy/api", 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+tc.path, nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func TestProxyForbiddenByFGA(t *testing.T) {
	database := setupInfra(t)
	srv, _ := startProxy(t, database, withAuthz(itDenyAll{}))
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/tenants/acme/clusters/c1/proxy/api", nil)
	req.Header.Set("Authorization", "Bearer good")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestProxyNoTunnel503(t *testing.T) {
	database := setupInfra(t)
	srv, _ := startProxy(t, database) // no agent connected
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/tenants/acme/clusters/c1/proxy/api", nil)
	req.Header.Set("Authorization", "Bearer good")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "upgrade the inari-agent chart") {
		t.Errorf("503 body lacks remediation text: %s", body)
	}
}

func TestProxyFlagOff410(t *testing.T) {
	database := setupInfra(t)
	srv, _ := startProxy(t, database, withFlags(StaticFlagEvaluator{Enabled: false}))
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/tenants/acme/clusters/c1/proxy/api", nil)
	req.Header.Set("Authorization", "Bearer good")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestProxyMaxLifetimeReaper(t *testing.T) {
	database := setupInfra(t)
	srv, sessions := startProxy(t, database, withMaxLifetime(300*time.Millisecond))
	// Hanging apiserver: 200 head, then a byte every so often, never EOF —
	// the max-lifetime reaper must cut the conn.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		for {
			if _, err := w.Write([]byte("x")); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(100 * time.Millisecond)
		}
	}))
	defer upstream.Close()
	agent := startFakeAgent(t, srv.URL, upstream)
	waitForSession(t, sessions, "c1")
	defer agent.close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/tenants/acme/clusters/c1/proxy/api", nil)
	req.Header.Set("Authorization", "Bearer good")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	events := waitOutbox(t, database, 2)
	var closePayload types.KubectlProxyPayload
	if err := json.Unmarshal(events[1].Payload, &closePayload); err != nil {
		t.Fatal(err)
	}
	if closePayload.Reason != CloseReasonMaxLifetime {
		t.Fatalf("close reason = %q, want %q", closePayload.Reason, CloseReasonMaxLifetime)
	}
}

func TestProxyUpgradeSplice(t *testing.T) {
	database := setupInfra(t)
	srv, sessions := startProxy(t, database)
	// Fake apiserver that upgrades and echoes bytes back uppercased.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Impersonate-User") != "dev@acme.example" {
			t.Errorf("upgrade request missing impersonation: %v", r.Header)
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("upstream not hijackable")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		buf.Flush()
		b := make([]byte, 4096)
		for {
			n, err := conn.Read(b)
			if n > 0 {
				conn.Write([]byte(strings.ToUpper(string(b[:n]))))
			}
			if err != nil {
				return
			}
		}
	}))
	defer upstream.Close()
	agent := startFakeAgent(t, srv.URL, upstream)
	waitForSession(t, sessions, "c1")
	defer agent.close()

	// Raw client: kubectl-style upgrade request.
	addr := strings.TrimPrefix(srv.URL, "http://")
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	fmt.Fprintf(raw, "GET /api/v1/tenants/acme/clusters/c1/proxy/api/v1/namespaces/default/pods/x/exec HTTP/1.1\r\n"+
		"Host: %s\r\nAuthorization: Bearer good\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", addr)
	br := bufio.NewReader(raw)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("status line = %q, %v", status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	if _, err := raw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "HELLO" {
		t.Fatalf("echo = %q", got)
	}
}
