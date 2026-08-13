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

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/config"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/logging"
	"github.com/7K-Inari/inari-server/internal/tenancy"
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

	router, api := httpserver.NewRouter(log, validator, database)
	handler.RegisterRoutes(api)

	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: router, ReadHeaderTimeout: 10 * time.Second}
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
