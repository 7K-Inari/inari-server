// export-openapi renders the full REST surface of the inari-server control
// plane to OpenAPI YAML without requiring any infrastructure (PostgreSQL,
// Keycloak, OpenFGA, NATS). Routes are registered through the shared
// restsurface registry — the same function the live binary
// (cmd/inari-server) uses — with nil services/dependencies: constructors
// and route registration never dereference them (dependencies are only
// touched per-request). A route that must not appear in this spec is marked
// huma Hidden: true on its Operation; omitting a module from the registry
// is never the mechanism for hiding routes.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/restsurface"
)

// buildAPI constructs the huma API exactly like cmd/inari-server does and
// registers every module's routes (with nil services/dependencies) via the
// shared restsurface registry.
func buildAPI() huma.API {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, api := httpserver.NewRouter(log, nil, nil)
	restsurface.Register(api, restsurface.Deps{})
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
