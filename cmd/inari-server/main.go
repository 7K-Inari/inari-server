// inari-server is the Inari control plane: a modular monolith where each
// module lives behind a strict internal interface (see AGENTS.md §5.2).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/7K-Inari/inari-server/internal/agentgateway"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/capabilities"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/config"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/logging"
	"github.com/7K-Inari/inari-server/internal/tenancy"

	"connectrpc.com/connect"
	agentv1connect "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1/agentv1connect"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
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
	if err := database.Migrate(ctx); err != nil {
		return err
	}

	validator, err := authn.NewOIDCValidator(ctx, cfg.OIDCIssuerURL, cfg.OIDCClientID)
	if err != nil {
		return err
	}

	fgaStore, err := authz.NewOpenFGAStore(ctx, cfg.OpenFGAAPIURL, cfg.OpenFGAStoreName)
	if err != nil {
		return err
	}
	authorizer := authz.NewAuthorizer(fgaStore)

	auditStore := audit.NewStore()
	dispatcher := audit.NewDispatcher(database, cfg.OutboxPollInterval, authz.NewTupleWriter(fgaStore))
	go dispatcher.Run(ctx)

	idp := tenancy.NewKeycloakAdmin(cfg.KeycloakBaseURL, cfg.KeycloakRealm, cfg.KeycloakAdminUser, cfg.KeycloakAdminPass)
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), auditStore)
	handler := tenancy.NewHandler(svc, authorizer)

	registry := clusterregistry.NewService(database, idp, clusterregistry.NewStore(), auditStore,
		cfg.RegistrationTokenTTL, cfg.EnrollmentApprovalRequired)
	registryHandler := clusterregistry.NewHandler(registry, svc, authorizer, clusterregistry.ManifestParams{
		AgentImageRepo: cfg.AgentImageRepo,
		AgentImageTag:  cfg.AgentImageTag,
		GatewayAddress: cfg.AgentGatewayAddress,
	})
	caps := capabilities.NewService(database, capabilities.NewStore(), auditStore)
	gateway := agentgateway.NewGateway(database, registry, idp, caps, auditStore, agentgateway.Config{
		OIDCIssuerURL:  cfg.OIDCIssuerURL,
		ESOSecretStore: cfg.ESOSecretStore,
	})

	router, api := httpserver.NewRouter(log, validator, database)
	handler.RegisterRoutes(api)
	registryHandler.RegisterRoutes(api)

	// Agent-facing Connect-RPC services mount on chi directly, outside the
	// huma bearer middleware: registration is token-authenticated, the event
	// stream authenticates via its own interceptor (cluster_id claim).
	regPath, regHandler := agentv1connect.NewRegistrationServiceHandler(gateway)
	streamPath, streamHandler := agentv1connect.NewEventStreamServiceHandler(gateway,
		connect.WithInterceptors(agentgateway.AuthInterceptor(validator)))
	router.Handle(regPath+"*", regHandler)
	router.Handle(streamPath+"*", streamHandler)

	// Unencrypted HTTP/2 (h2c) so Connect-RPC streaming works without TLS
	// termination in front (agents may dial directly in dev).
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		Protocols:         protocols,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
