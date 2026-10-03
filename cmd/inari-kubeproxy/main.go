// inari-kubeproxy is the kubectl gateway data plane (plan §7.2): it
// terminates user kubectl TLS on /proxy/*, validates Keycloak JWTs
// statelessly (JWKS), checks OpenFGA cluster:kubectl per request, mints
// Impersonate-* headers, and muxes requests onto per-cluster tunnel streams
// dialed out by in-cluster inari-tunnel-agents. The control plane
// (inari-server) carries zero tunnel bytes.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/cache"
	"github.com/7K-Inari/inari-server/internal/config"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/kubeproxy"
	"github.com/7K-Inari/inari-server/internal/logging"
	"github.com/7K-Inari/inari-server/internal/metrics"
	"github.com/7K-Inari/inari-server/internal/tenancy"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadKubeproxy()
	if err != nil {
		return err
	}
	log := logging.New(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	database, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer database.Close()

	// Stateless JWT validators (JWKS via OIDC discovery): users present
	// kubelogin tokens (aud kubernetes); tunnel agents present
	// client-credentials tokens from tunnel-<cluster-id> clients.
	userValidator, err := authn.NewOIDCValidator(ctx, cfg.OIDCIssuerURL, cfg.UserAudience)
	if err != nil {
		return err
	}
	agentValidator, err := authn.NewOIDCValidator(ctx, cfg.OIDCIssuerURL, tenancy.TunnelAudience)
	if err != nil {
		return err
	}

	fgaStore, err := authz.NewOpenFGAStore(ctx, cfg.OpenFGAAPIURL, cfg.OpenFGAStoreName)
	if err != nil {
		return err
	}
	cacheBackend, err := cache.New(cache.Config{
		Backend:          cfg.CacheBackend,
		RedisURL:         cfg.RedisURL,
		MemoryMaxEntries: cfg.CacheMemoryMaxEntries,
	})
	if err != nil {
		return err
	}
	defer func() { _ = cacheBackend.Close(context.Background()) }()
	// PEP cache, ADR-0010: Check results cached INARI_CACHE_PEP_TTL; cache
	// failures fail open to direct OpenFGA calls (logged + metered).
	authorizer := authz.NewCachedAuthorizer(authz.NewAuthorizer(fgaStore), cacheBackend, cfg.CacheBackend, cfg.CachePEPTTL)

	metricsHandler, metricsShutdown, err := metrics.New()
	if err != nil {
		return err
	}
	defer func() { _ = metricsShutdown(context.Background()) }()

	flags := kubeproxy.StaticFlagEvaluator{Enabled: cfg.KubectlAccessEnabled}
	sessions := kubeproxy.NewSessionRegistry()
	hostname, _ := os.Hostname()

	proxy := kubeproxy.NewProxyHandler(kubeproxy.ProxyConfig{
		Flags:       flags,
		Validator:   userValidator,
		Authz:       authorizer,
		Sessions:    sessions,
		DB:          database,
		Audit:       audit.NewStore(),
		MaxLifetime: cfg.MaxTunnelLifetime,
		OpenTimeout: cfg.OpenResultTimeout,
	})

	router, err := kubeproxy.NewServer(kubeproxy.ServerConfig{
		Proxy:          proxy,
		Flags:          flags,
		Sessions:       sessions,
		Heartbeat:      kubeproxy.NewHeartbeatWriter(database.Pool, hostname),
		AgentAuth:      agentValidator,
		ByteCap:        cfg.ConnByteCap,
		Ready:          database.Ping,
		MetricsHandler: metricsHandler,
	})
	if err != nil {
		return err
	}

	// h2c so Connect-RPC streaming works without TLS termination in front;
	// HTTP/1.1 stays enabled for kubectl and health checks (same pattern as
	// cmd/inari-server).
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: router,
		// No ReadHeaderTimeout: bidi tunnel streams are long-lived; timeouts
		// belong at the LB/Ingress layer.
		Protocols: protocols,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	sessions.CloseAll("shutdown")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
