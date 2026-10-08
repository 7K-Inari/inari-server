package kubeproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	tunnelv2 "github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v2"
	"github.com/google/uuid"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/metrics"
	"github.com/7K-Inari/inari-server/internal/types"
)

// MaxTunnelFrame mirrors the contract's 32 KiB frame bound.
const MaxTunnelFrame = 32 << 10

// Defaults for the proxy handler.
const (
	DefaultOpenResultTimeout = 30 * time.Second
	DefaultMaxTunnelLifetime = 60 * time.Minute
)

// Checker is the narrow FGA seam the proxy needs (satisfied by
// authz.CachedAuthorizer; ADR-0010 fail-open lives inside it).
type Checker interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
}

// ProxyConfig wires the user-facing proxy handler.
type ProxyConfig struct {
	Flags       FlagEvaluator
	Validator   authn.Validator // user JWTs (aud kubernetes), stateless JWKS
	Authz       Checker
	Sessions    *SessionRegistry
	DB          *db.DB
	Audit       *audit.Store
	MaxLifetime time.Duration // per-conn re-auth bound (plan §7 risk 4)
	OpenTimeout time.Duration
}

// ProxyHandler terminates user kubectl requests and tunnels them over the
// cluster's live tunnel-agent session.
type ProxyHandler struct {
	cfg ProxyConfig
	// orgIDs caches slug → organizations.id for audit attribution.
	orgIDs sync.Map
}

// NewProxyHandler builds the handler; zero durations fall back to defaults.
func NewProxyHandler(cfg ProxyConfig) *ProxyHandler {
	if cfg.MaxLifetime <= 0 {
		cfg.MaxLifetime = DefaultMaxTunnelLifetime
	}
	if cfg.OpenTimeout <= 0 {
		cfg.OpenTimeout = DefaultOpenResultTimeout
	}
	if cfg.Sessions == nil {
		cfg.Sessions = NewSessionRegistry()
	}
	return &ProxyHandler{cfg: cfg}
}

// hopByHop are stripped from forwarded heads (the tunnel agent re-creates
// the transport-level request; upgrade intent rides TunnelOpen).
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding",
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := r.PathValue("org")
	clusterID := r.PathValue("id")

	if !h.cfg.Flags.KubectlAccessEnabled(ctx) {
		http.Error(w, `{"error":"kubectl access is disabled by platform policy"}`, http.StatusGone)
		return
	}
	raw, err := bearerToken(r)
	if err != nil {
		http.Error(w, `{"error":"missing or malformed authorization header"}`, http.StatusUnauthorized)
		return
	}
	id, err := h.cfg.Validator.Validate(ctx, raw)
	if err != nil {
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}
	// Coarse PEP: the tenant comes from the token, never the URL.
	if !id.MemberOf(org) {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}
	// Fine PEP: FGA cluster:kubectl per request (cached, fail-open).
	allowed, err := h.cfg.Authz.Check(ctx, authz.UserObject(id.Subject), authz.RelationKubectl, authz.ClusterObject(clusterID))
	if err != nil {
		slog.Error("kubeproxy: FGA check failed", "cluster", clusterID, "error", err)
		http.Error(w, `{"error":"authorization unavailable"}`, http.StatusBadGateway)
		return
	}
	if !allowed {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}
	sess := h.cfg.Sessions.Get(clusterID)
	if sess == nil {
		metrics.RecordKubeproxyConn(ctx, metrics.KubeproxyNoTunnel)
		http.Error(w, `{"error":"tunnel unavailable: no tunnel agent is connected for this cluster — upgrade the inari-agent chart to a version with kubectl tunnel support"}`,
			http.StatusServiceUnavailable)
		return
	}
	orgID, err := h.resolveOrgID(ctx, org)
	if err != nil {
		slog.Error("kubeproxy: resolve org", "org", org, "error", err)
		http.Error(w, `{"error":"tenant resolution failed"}`, http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(ctx, h.cfg.MaxLifetime)
	defer cancel()

	connID := uuid.NewString()
	conn := sess.mux.alloc(connID)
	defer sess.mux.remove(connID)

	hdr := r.Header.Clone()
	for _, k := range hopByHop {
		hdr.Del(k)
	}
	hdr.Del("Authorization") // user tokens never reach the cluster
	hdr.Del("Host")
	StripImpersonateHeaders(hdr)
	user := id.Email
	if user == "" {
		user = id.Subject
	}
	MintImpersonateHeaders(hdr, user, id.Groups, org)

	path := "/" + r.PathValue("*")
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	upgrade := isUpgrade(r)

	// Audit at open; audit is mandatory — a failed write fails the request.
	if err := h.appendOutbox(ctx, orgID, types.EventClusterKubectlProxyOpen, types.KubectlProxyPayload{
		OrgID: orgID, ClusterID: clusterID, ConnectionID: connID, UserID: id.Subject,
		Method: r.Method, Path: path,
	}); err != nil {
		slog.Error("kubeproxy: audit open failed", "cluster", clusterID, "error", err)
		http.Error(w, `{"error":"audit unavailable"}`, http.StatusInternalServerError)
		return
	}
	metrics.RecordKubeproxyConn(ctx, metrics.KubeproxyOpen)
	start := time.Now()
	defer func() {
		reason := conn.CloseReason()
		if reason == "" {
			reason = CloseReasonDone
		}
		// Tell the agent to drop the conn (best-effort; the session may be
		// gone already).
		_ = sess.Send(closeMsg(connID, reason))
		if err := h.appendOutbox(context.Background(), orgID, types.EventClusterKubectlProxyClose, types.KubectlProxyPayload{
			OrgID: orgID, ClusterID: clusterID, ConnectionID: connID, UserID: id.Subject,
			Method: r.Method, Path: path,
			DurationMs: time.Since(start).Milliseconds(),
			BytesIn:    conn.bytesIn.Load(), BytesOut: conn.bytesOut.Load(), Reason: reason,
		}); err != nil {
			slog.Error("kubeproxy: audit close failed", "cluster", clusterID, "error", err)
		}
		metrics.RecordKubeproxyConn(context.Background(), metrics.KubeproxyClose)
	}()

	open := &tunnelv2.TunnelMessage{
		ConnectionId: connID,
		Payload: &tunnelv2.TunnelMessage_Open{Open: &tunnelv2.TunnelOpen{
			Method: r.Method, Path: path, Headers: flattenHeader(hdr), UpgradeExpected: upgrade,
		}},
	}
	if err := sess.Send(open); err != nil {
		slog.Warn("kubeproxy: tunnel send open", "cluster", clusterID, "error", err)
		http.Error(w, `{"error":"tunnel write failed"}`, http.StatusServiceUnavailable)
		return
	}

	// Non-upgrade requests with a body stream it concurrently as frames.
	if !upgrade && r.Body != nil {
		go h.pumpToAgent(ctx, sess, conn, r.Body)
	}

	result, err := h.awaitOpenResult(ctx, conn)
	if err != nil {
		slog.Warn("kubeproxy: open result", "cluster", clusterID, "conn", connID, "error", err)
		// Best-effort: tell the agent to drop the conn.
		_ = sess.Send(closeMsg(conn.id, "open_failed"))
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadGateway)
		return
	}

	if result.GetStatus() == http.StatusSwitchingProtocols {
		h.spliceUpgrade(ctx, w, r, sess, conn, result)
		return
	}

	writeHead(w, result)
	flusher, _ := w.(http.Flusher)
	for {
		select {
		case <-ctx.Done():
			conn.close(CloseReasonMaxLifetime)
			_ = sess.Send(closeMsg(connID, CloseReasonMaxLifetime))
			return
		case <-conn.closed:
			// route() closes the conn on TunnelClose without queueing behind
			// buffered frames — flush any data already delivered first, or a
			// close racing a buffered frame drops the tail of the response.
			if err := drainPendingFrames(conn, func(b []byte) error {
				_, err := w.Write(b)
				return err
			}); err == nil && flusher != nil {
				flusher.Flush()
			}
			return
		case msg := <-conn.fromAgent:
			f := msg.GetFrame()
			if f == nil {
				continue
			}
			if len(f.GetData()) > 0 {
				if _, err := w.Write(f.GetData()); err != nil {
					conn.close("client_write_failed")
					_ = sess.Send(closeMsg(connID, "client_write_failed"))
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if f.GetHalfClose() {
				return
			}
		}
	}
}

// drainPendingFrames writes any agent data frames already buffered in
// conn.fromAgent when the conn closed. connMux.route closes the conn
// immediately on TunnelClose without queueing behind buffered frames, so a
// close racing a buffered data frame would otherwise drop the tail of the
// response. Frames after the close are impossible (the agent sends close
// last and route delivers in order), so the non-blocking drain is complete.
func drainPendingFrames(conn *proxyConn, write func([]byte) error) error {
	for {
		select {
		case msg := <-conn.fromAgent:
			f := msg.GetFrame()
			if f == nil || len(f.GetData()) == 0 {
				continue
			}
			if err := write(f.GetData()); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

// pumpToAgent streams the request body (or hijacked conn) to the agent as
// frames, ending with a half-close frame at EOF.
func (h *ProxyHandler) pumpToAgent(ctx context.Context, sess *Session, conn *proxyConn, body io.Reader) {
	buf := make([]byte, MaxTunnelFrame)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if !sess.mux.countIn(conn, n) {
				conn.close(CloseReasonByteCapExceeded)
				metrics.RecordKubeproxyConn(ctx, metrics.KubeproxyByteCapExceeded)
				_ = sess.Send(closeMsg(conn.id, CloseReasonByteCapExceeded))
				return
			}
			msg := &tunnelv2.TunnelMessage{
				ConnectionId: conn.id,
				Payload: &tunnelv2.TunnelMessage_Frame{Frame: &tunnelv2.TunnelFrame{
					Data: buf[:n],
				}},
			}
			if sendErr := sess.Send(msg); sendErr != nil {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				_ = sess.Send(&tunnelv2.TunnelMessage{
					ConnectionId: conn.id,
					Payload:      &tunnelv2.TunnelMessage_Frame{Frame: &tunnelv2.TunnelFrame{HalfClose: true}},
				})
			} else if !errors.Is(err, context.Canceled) {
				_ = sess.Send(closeMsg(conn.id, "client_read_failed"))
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// awaitOpenResult waits for the agent's TunnelOpenResult (or a terminal
// conn state) with the open timeout.
func (h *ProxyHandler) awaitOpenResult(ctx context.Context, conn *proxyConn) (*tunnelv2.TunnelOpenResult, error) {
	timer := time.NewTimer(h.cfg.OpenTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("request cancelled")
		case <-timer.C:
			return nil, fmt.Errorf("tunnel open timed out")
		case <-conn.closed:
			return nil, fmt.Errorf("tunnel closed during open: %s", conn.CloseReason())
		case msg := <-conn.fromAgent:
			switch {
			case msg.GetOpenResult() != nil:
				res := msg.GetOpenResult()
				if res.GetError() != "" {
					return nil, fmt.Errorf("agent dial failed: %s", res.GetError())
				}
				return res, nil
			case msg.GetClose() != nil:
				return nil, fmt.Errorf("tunnel closed during open: %s", msg.GetClose().GetReason())
			default:
				// Frames before the head are a protocol violation; ignore.
			}
		}
	}
}

// spliceUpgrade handles 101 responses (SPDY/websocket exec, port-forward):
// hijack the client conn, write the raw head, then splice bytes both ways.
func (h *ProxyHandler) spliceUpgrade(ctx context.Context, w http.ResponseWriter, r *http.Request, sess *Session, conn *proxyConn, result *tunnelv2.TunnelOpenResult) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, `{"error":"upgrade unsupported"}`, http.StatusInternalServerError)
		return
	}
	raw, buf, err := hijacker.Hijack()
	if err != nil {
		slog.Warn("kubeproxy: hijack", "error", err)
		return
	}
	defer func() { _ = raw.Close() }()

	if _, err := fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return
	}
	// The agent relays the apiserver's 101 headers verbatim, including
	// Connection/Upgrade — skip those here and emit exactly one pair, or
	// the spliced head carries duplicates. The apiserver's Upgrade token
	// (the negotiated protocol) wins over the client's request value.
	upgradeProto := r.Header.Get("Upgrade")
	for k, vs := range result.GetHeaders() {
		switch strings.ToLower(k) {
		case "connection":
			continue
		case "upgrade":
			if len(vs.GetValues()) > 0 {
				upgradeProto = vs.GetValues()[0]
			}
			continue
		}
		for _, v := range vs.GetValues() {
			if _, err := fmt.Fprintf(buf, "%s: %s\r\n", k, v); err != nil {
				return
			}
		}
	}
	if _, err := fmt.Fprintf(buf, "Connection: Upgrade\r\nUpgrade: %s\r\n\r\n", upgradeProto); err != nil {
		return
	}
	if err := buf.Flush(); err != nil {
		return
	}

	// Client → agent (stdin). Read from the hijacked bufio.Reader, not the
	// raw conn: the server read-aheads pipelined bytes (kubectl port-forward
	// sends protocol frames immediately post-request) into buf, and reading
	// raw directly would silently drop them (M1W9 N3c).
	go h.pumpToAgent(ctx, sess, conn, buf)
	// Agent → client (stdout/stderr channel frames).
	for {
		select {
		case <-ctx.Done():
			conn.close(CloseReasonMaxLifetime)
			_ = sess.Send(closeMsg(conn.id, CloseReasonMaxLifetime))
			return
		case <-conn.closed:
			// Same drain as the non-upgrade loop: don't drop buffered frames.
			_ = drainPendingFrames(conn, func(b []byte) error {
				_, err := raw.Write(b)
				return err
			})
			return
		case msg := <-conn.fromAgent:
			f := msg.GetFrame()
			if f == nil {
				continue
			}
			if len(f.GetData()) > 0 {
				if _, err := raw.Write(f.GetData()); err != nil {
					conn.close("client_write_failed")
					_ = sess.Send(closeMsg(conn.id, "client_write_failed"))
					return
				}
			}
			if f.GetHalfClose() {
				// Agent finished sending; our write side ends with the conn.
				return
			}
		}
	}
}

// resolveOrgID maps a tenant slug to organizations.id for audit rows,
// cached for the process lifetime (slugs are immutable).
func (h *ProxyHandler) resolveOrgID(ctx context.Context, slug string) (string, error) {
	if v, ok := h.orgIDs.Load(slug); ok {
		return v.(string), nil
	}
	var id string
	if err := h.cfg.DB.Pool.QueryRow(ctx,
		`SELECT id FROM organizations WHERE slug = $1`, slug).Scan(&id); err != nil {
		return "", err
	}
	h.orgIDs.Store(slug, id)
	return id, nil
}

func (h *ProxyHandler) appendOutbox(ctx context.Context, orgID, eventType string, payload types.KubectlProxyPayload) error {
	if h.cfg.DB == nil {
		return nil
	}
	return audit.AppendOutbox(ctx, h.cfg.DB.Pool, orgID, eventType, payload)
}

func closeMsg(connID, reason string) *tunnelv2.TunnelMessage {
	return &tunnelv2.TunnelMessage{
		ConnectionId: connID,
		Payload:      &tunnelv2.TunnelMessage_Close{Close: &tunnelv2.TunnelClose{Reason: reason}},
	}
}

func isUpgrade(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		r.Header.Get("Upgrade") != ""
}

func flattenHeader(h http.Header) map[string]*tunnelv2.StringList {
	out := make(map[string]*tunnelv2.StringList, len(h))
	for k, vs := range h {
		out[k] = &tunnelv2.StringList{Values: vs}
	}
	return out
}

func writeHead(w http.ResponseWriter, result *tunnelv2.TunnelOpenResult) {
	hop := map[string]bool{"Connection": true, "Keep-Alive": true, "Te": true, "Trailer": true, "Transfer-Encoding": true}
	for k, v := range result.GetHeaders() {
		if hop[http.CanonicalHeaderKey(k)] {
			continue
		}
		w.Header()[http.CanonicalHeaderKey(k)] = v.GetValues()
	}
	status := int(result.GetStatus())
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
}

func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errors.New("no authorization header")
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		return "", errors.New("malformed authorization header")
	}
	return parts[1], nil
}
