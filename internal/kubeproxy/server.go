package kubeproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/go-chi/chi/v5"

	tunnelv1 "github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v1"
	"github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v1/tunnelv1connect"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/metrics"
)

// pingHeartbeatInterval throttles heartbeat refreshes on stream pings.
const pingHeartbeatInterval = 15 * time.Second

// ServerConfig wires the kubeproxy HTTP/tunnel surface.
type ServerConfig struct {
	Proxy     *ProxyHandler
	Flags     FlagEvaluator
	Sessions  *SessionRegistry // must match ProxyConfig.Sessions
	Heartbeat *HeartbeatWriter // nil disables liveness writes
	AgentAuth authn.Validator  // tunnel-agent JWTs (client-credentials, cluster_id)
	ByteCap   int64            // per-conn byte cap; 0 = unlimited
	// Ready reports readiness (e.g. DB ping); nil = always ready.
	Ready func(ctx context.Context) error
	// MetricsHandler serves /metrics; nil = no metrics route.
	MetricsHandler http.Handler
}

// TunnelHandler implements tunnelv1connect.TunnelServiceHandler: the
// tunnel-agent bidi stream endpoint.
type TunnelHandler struct {
	tunnelv1connect.UnimplementedTunnelServiceHandler
	flags     FlagEvaluator
	sessions  *SessionRegistry
	heartbeat *HeartbeatWriter
	byteCap   int64
}

// NewServer builds the chi router: the user proxy route plus the
// TunnelService Connect handler on one port (h2c is enabled by the caller's
// http.Server — same pattern as cmd/inari-server).
func NewServer(cfg ServerConfig) (http.Handler, error) {
	r := chi.NewRouter()

	tunnel := &TunnelHandler{
		flags: cfg.Flags, sessions: cfg.Sessions, heartbeat: cfg.Heartbeat, byteCap: cfg.ByteCap,
	}
	path, handler := tunnelv1connect.NewTunnelServiceHandler(tunnel,
		connect.WithInterceptors(AgentAuthInterceptor(cfg.AgentAuth)))
	r.Handle(path+"*", handler)

	r.Method(http.MethodGet, "/api/v1/tenants/{org}/clusters/{id}/proxy/*", cfg.Proxy)
	r.Method(http.MethodPost, "/api/v1/tenants/{org}/clusters/{id}/proxy/*", cfg.Proxy)
	r.Method(http.MethodPut, "/api/v1/tenants/{org}/clusters/{id}/proxy/*", cfg.Proxy)
	r.Method(http.MethodPatch, "/api/v1/tenants/{org}/clusters/{id}/proxy/*", cfg.Proxy)
	r.Method(http.MethodDelete, "/api/v1/tenants/{org}/clusters/{id}/proxy/*", cfg.Proxy)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Ready != nil {
			if err := cfg.Ready(r.Context()); err != nil {
				http.Error(w, "not ready", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	if cfg.MetricsHandler != nil {
		r.Handle("/metrics", cfg.MetricsHandler)
	}
	return r, nil
}

// Connect admits one tunnel-agent stream per cluster (fenced
// last-writer-wins), records the heartbeat, and routes agent→proxy messages
// into the session mux until the stream ends.
func (h *TunnelHandler) Connect(ctx context.Context, stream *connect.BidiStream[tunnelv1.TunnelMessage, tunnelv1.TunnelMessage]) error {
	id := AgentIdentityFromContext(ctx)
	if id == nil {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))
	}
	clusterID := id.ClusterID

	// Flag off: reject new tunnels (static evaluator — a dynamic flip also
	// calls SessionRegistry.CloseAll).
	if !h.flags.KubectlAccessEnabled(ctx) {
		return connect.NewError(connect.CodeUnavailable, errors.New("kubectl access is disabled by platform policy"))
	}

	sess := newSession(ctx, clusterID, func(msg *tunnelv1.TunnelMessage) error {
		return stream.Send(msg)
	}, h.byteCap)
	h.sessions.Register(sess)
	metrics.RecordKubeproxySession(ctx, metrics.KubeproxySessionRegister)
	if h.heartbeat != nil {
		if err := h.heartbeat.Connected(ctx, clusterID); err != nil {
			slog.Warn("kubeproxy: heartbeat connect write failed", "cluster", clusterID, "error", err)
		}
	}
	defer func() {
		h.sessions.Unregister(sess)
		sess.close(CloseReasonTunnelClosed)
		// Quiesce in-flight Sends before returning: after the handler
		// returns, connect writes the end-stream envelope to the same
		// response writer that Session.Send uses, so an in-flight proxied
		// send (closeMsg, open, frames) would race it (found by -race).
		sess.drain()
		metrics.RecordKubeproxySession(context.Background(), metrics.KubeproxySessionUnregister)
		// Only delete the heartbeat row when no replacement session has
		// taken over: on last-writer-wins eviction the new session already
		// upserted its row, and deleting it would report a live tunnel as
		// unavailable until the next reconnect.
		if h.heartbeat != nil && h.sessions.Get(clusterID) == nil {
			if err := h.heartbeat.Disconnected(context.Background(), clusterID); err != nil {
				slog.Warn("kubeproxy: heartbeat disconnect write failed", "cluster", clusterID, "error", err)
			}
		}
	}()

	slog.Info("kubeproxy: tunnel agent connected", "cluster", clusterID, "session", sess.id)
	lastBeat := time.Now()
	for {
		msg, err := stream.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) {
				slog.Info("kubeproxy: tunnel agent disconnected", "cluster", clusterID, "session", sess.id)
				return nil
			}
			// Eviction cancels the stream context.
			if errors.Is(ctx.Err(), context.Canceled) {
				select {
				case <-sess.done:
					slog.Info("kubeproxy: tunnel session evicted by reconnect", "cluster", clusterID, "session", sess.id)
					return nil
				default:
				}
			}
			return err
		}
		switch {
		case msg.GetPing() != nil:
			if h.heartbeat != nil && time.Since(lastBeat) >= pingHeartbeatInterval {
				if err := h.heartbeat.Seen(ctx, clusterID); err != nil {
					slog.Warn("kubeproxy: heartbeat refresh failed", "cluster", clusterID, "error", err)
				}
				lastBeat = time.Now()
			}
		default:
			// open_result / frame / close: route to the owning conn.
			sess.mux.route(msg)
		}
	}
}
