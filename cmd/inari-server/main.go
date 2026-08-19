// inari-server is the Inari control plane: a modular monolith where each
// module lives behind a strict internal interface (see AGENTS.md §5.2).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/7K-Inari/inari-server/internal/agentgateway"
	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/capabilities"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/cloudaccounts"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/config"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/logging"
	"github.com/7K-Inari/inari-server/internal/notifications"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	gitgithub "github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider/github"
	"github.com/7K-Inari/inari-server/internal/policyservice"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"

	"connectrpc.com/connect"
	agentv1connect "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1/agentv1connect"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// agentgatewayStatusSink adapts inventory.Service to the gateway StatusSink.
type agentgatewayStatusSink struct{ inv *inventory.Service }

func (s agentgatewayStatusSink) ApplyStatus(ctx context.Context, clusterID string, upd agentgateway.StatusUpdate) (bool, error) {
	return s.inv.ApplyStatus(ctx, clusterID, inventory.StatusUpdate{
		Resource: upd.Resource, Health: upd.Health, Sync: upd.Sync, Message: upd.Message,
	})
}

// policyCheckerAdapter maps the orchestrator's policy seam onto the Policy
// Service (plan §5.11).
type policyCheckerAdapter struct{ ps *policyservice.Service }

func (a policyCheckerAdapter) PreFlight(ctx context.Context, in orchestrator.PolicyInput) (*types.PolicyDecision, error) {
	return a.ps.PreFlight(ctx, policyservice.PreFlightInput{
		OrgID: in.OrgID, ItemID: in.ItemID, Version: in.Version, ClusterID: in.ClusterID,
		Spec: in.Spec, Requester: in.Requester,
		ClusterLabels: in.ClusterLabels, ClusterDistribution: in.ClusterDistribution,
	})
}

func (a policyCheckerAdapter) RenderCheck(ctx context.Context, orgID string, manifests ...[]byte) (*types.PolicyDecision, error) {
	return a.ps.RenderCheck(ctx, orgID, manifests...)
}

// buildGitProvider selects the git backend (fake for dev/tests; GitHub App
// credentials in production, §12.1/2).
func buildGitProvider(cfg *config.Config) (gitprovider.Provider, error) {
	if cfg.GitProvider == "github" {
		return gitgithub.New(gitgithub.Config{
			AppID:          cfg.GitHubAppID,
			InstallationID: cfg.GitHubInstallationID,
			PrivateKeyFile: cfg.GitHubAppPrivateKeyFile,
		})
	}
	return gitprovider.NewFake(), nil
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

	idp := tenancy.NewKeycloakAdmin(cfg.KeycloakBaseURL, cfg.KeycloakRealm, cfg.KeycloakAdminUser, cfg.KeycloakAdminPass)
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), auditStore)
	handler := tenancy.NewHandler(svc, authorizer)

	registry := clusterregistry.NewService(database, idp, clusterregistry.NewStore(), auditStore,
		cfg.RegistrationTokenTTL, cfg.EnrollmentApprovalRequired)
	capsStore := capabilities.NewStore()
	registryHandler := clusterregistry.NewHandler(registry, svc, authorizer, clusterregistry.ManifestParams{
		AgentImageRepo: cfg.AgentImageRepo,
		AgentImageTag:  cfg.AgentImageTag,
		GatewayAddress: cfg.AgentGatewayAddress,
	}, clusterregistry.CapabilitiesListerFunc(func(ctx context.Context, clusterID string) ([]types.Capability, error) {
		return capsStore.List(ctx, database.Pool, clusterID)
	}))
	caps := capabilities.NewService(database, capsStore, auditStore)
	gateway := agentgateway.NewGateway(database, registry, idp, caps, auditStore, agentgateway.Config{
		OIDCIssuerURL:  cfg.OIDCIssuerURL,
		ESOSecretStore: cfg.ESOSecretStore,
	})

	var puller catalog.OCIPuller
	if cfg.CatalogOCIPath != "" {
		puller = &catalog.FixturePuller{Root: cfg.CatalogOCIPath}
	}
	catalogSvc := catalog.NewService(database, catalog.NewStore(), capabilities.NewStore(), auditStore, puller)
	catalogHandler := catalog.NewHandler(catalogSvc, svc, authorizer)
	if err := catalogSvc.SeedPlatformApps(ctx); err != nil {
		return err
	}
	if puller != nil {
		if _, err := catalogSvc.Sync(ctx); err != nil {
			return fmt.Errorf("catalog sync: %w", err)
		}
	}

	approvalsSvc := approvals.NewService(database, approvals.NewStore(database), auditStore, svc, catalogSvc)
	approvalsHandler := approvals.NewHandler(approvalsSvc, svc, authorizer)
	go approvalsSvc.RunExpiryLoop(ctx, time.Minute)

	inventorySvc := inventory.NewService(database, inventory.NewStore(), auditStore, catalogSvc)
	inventoryHandler := inventory.NewHandler(inventorySvc, svc, authorizer)
	gateway.SetStatusSink(agentgatewayStatusSink{inventorySvc})

	git, err := buildGitProvider(cfg)
	if err != nil {
		return err
	}
	orchestratorSvc := orchestrator.NewService(database, inventory.NewStore(), catalogSvc, registry,
		approvalsSvc, gateway.Queue(), git, auditStore)
	orchestratorHandler := orchestrator.NewHandler(orchestratorSvc, svc, authorizer)

	cloudAccountsSvc := cloudaccounts.NewService(database, cloudaccounts.NewStore(), auditStore, cloudaccounts.NewSTSValidator())
	cloudAccountsHandler := cloudaccounts.NewHandler(cloudAccountsSvc, svc, registry, authorizer)

	notificationsSvc := notifications.NewService(database, notifications.NewStore(), auditStore,
		notifications.NewSlackSender(nil), notifications.NewWebhookSender(nil))
	notificationsHandler := notifications.NewHandler(notificationsSvc, svc, authorizer)

	policySvc := policyservice.NewService(database, policyservice.NewStore(),
		policyservice.NewOPAEvaluator(), registry, gateway.Queue(), auditStore)
	policyHandler := policyservice.NewHandler(policySvc, svc, authorizer)
	orchestratorSvc.WithPolicyChecker(policyCheckerAdapter{policySvc})

	// Outbox consumers: FGA tuple writer, notifications, approval-gated
	// deploy resume (plan §5.2, §5.4). Constructed after every handler
	// exists so the dispatch table is never mutated while Run polls.
	dispatcher := audit.NewDispatcher(database, cfg.OutboxPollInterval,
		authz.NewTupleWriter(fgaStore),
		notificationsSvc,
		orchestrator.NewResumeHandler(orchestratorSvc, approvalsSvc, log),
		policyservice.NewDistributeHandler(policySvc, log),
	)
	go dispatcher.Run(ctx)

	router, api := httpserver.NewRouter(log, validator, database)
	handler.RegisterRoutes(api)
	registryHandler.RegisterRoutes(api)
	catalogHandler.RegisterRoutes(api)
	approvalsHandler.RegisterRoutes(api)
	inventoryHandler.RegisterRoutes(api)
	orchestratorHandler.RegisterRoutes(api)
	cloudAccountsHandler.RegisterRoutes(api)
	notificationsHandler.RegisterRoutes(api)
	policyHandler.RegisterRoutes(api)

	// Agent-facing Connect-RPC services mount on chi directly, outside the
	// huma bearer middleware: registration is token-authenticated, the event
	// stream authenticates via its own interceptor (cluster_id claim).
	regPath, regHandler := agentv1connect.NewRegistrationServiceHandler(gateway)
	streamPath, streamHandler := agentv1connect.NewEventStreamServiceHandler(gateway,
		connect.WithInterceptors(agentgateway.AuthInterceptor(validator)))
	router.Handle(regPath+"*", regHandler)
	router.Handle(streamPath+"*", streamHandler)

	// Unencrypted HTTP/2 (h2c) so Connect-RPC streaming works without TLS
	// termination in front (agents may dial directly in dev). HTTP/1.1 stays
	// enabled for REST clients, browsers and health checks.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	srv := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: router,
		// No ReadHeaderTimeout: with h2c bidi streams (agent EventStream) a
		// header deadline propagates to the stream and kills long-lived
		// connections at the timeout. Timeouts belong at the LB/proxy layer.
		Protocols: protocols,
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
