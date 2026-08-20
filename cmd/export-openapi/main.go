// export-openapi renders the full REST surface of the inari-server control
// plane to OpenAPI YAML without requiring any infrastructure (PostgreSQL,
// Keycloak, OpenFGA, NATS). Module handlers are constructed with nil
// services/dependencies: constructors and route registration never
// dereference them (dependencies are only touched per-request).
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/cloudaccounts"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/notifications"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/policyservice"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/tenantzonefactory"
)

// buildAPI constructs the huma API exactly like cmd/inari-server does and
// registers every module's routes with nil services/dependencies.
func buildAPI() huma.API {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, api := httpserver.NewRouter(log, nil, nil)

	tenancy.NewHandler(nil, nil).RegisterRoutes(api)
	clusterregistry.NewHandler(nil, nil, nil, clusterregistry.ManifestParams{}, nil).RegisterRoutes(api)
	catalog.NewHandler(nil, nil, nil).RegisterRoutes(api)
	approvals.NewHandler(nil, nil, nil).RegisterRoutes(api)
	inventory.NewHandler(nil, nil, nil).RegisterRoutes(api)
	orchestrator.NewHandler(nil, nil, nil).RegisterRoutes(api)
	cloudaccounts.NewHandler(nil, nil, nil, nil).RegisterRoutes(api)
	notifications.NewHandler(nil, nil, nil).RegisterRoutes(api)
	policyservice.NewHandler(nil, nil, nil).RegisterRoutes(api)
	tenantzonefactory.NewHandler(nil, nil, nil).RegisterRoutes(api)
	return api
}

func run(out io.Writer) error {
	yaml, err := buildAPI().OpenAPI().YAML()
	if err != nil {
		return fmt.Errorf("render openapi: %w", err)
	}
	_, err = out.Write(yaml)
	return err
}

func main() {
	out := io.Writer(os.Stdout)
	if len(os.Args) > 1 {
		f, err := os.Create(os.Args[1])
		if err != nil {
			slog.Error("create output file", "error", err)
			os.Exit(1)
		}
		defer func() { _ = f.Close() }()
		out = f
	}
	if err := run(out); err != nil {
		slog.Error("export-openapi", "error", err)
		os.Exit(1)
	}
}
