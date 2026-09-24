package main

import (
	"bytes"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/config"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/restsurface"
)

// operationSet returns the sorted "METHOD path" list of a huma API's
// rendered OpenAPI document. Operations marked Hidden: true never appear in
// the rendered spec, so they are excluded here by construction — Hidden is
// the supported mechanism for deliberately unpublished routes.
func operationSet(api huma.API) []string {
	var ops []string
	for path, item := range api.OpenAPI().Paths {
		for method, op := range map[string]*huma.Operation{
			"GET": item.Get, "PUT": item.Put, "POST": item.Post,
			"DELETE": item.Delete, "PATCH": item.Patch, "HEAD": item.Head,
			"OPTIONS": item.Options, "TRACE": item.Trace,
		} {
			if op != nil {
				ops = append(ops, method+" "+path)
			}
		}
	}
	sort.Strings(ops)
	return ops
}

// TestExportParityWithLiveWiring asserts the offline-exported spec has a
// path+method set identical to the live wiring (restsurface.Register with
// the config-shaped deps cmd/inari-server passes). Both sides share the
// same registration function, so this guards against buildAPI adding or
// skipping anything and against config scalars changing the route set.
// Deliberate exclusions use huma Hidden: true per operation (see
// internal/restsurface and AGENTS.md).
func TestExportParityWithLiveWiring(t *testing.T) {
	exported := operationSet(buildAPI())

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, liveAPI := httpserver.NewRouter(log, nil, nil)
	restsurface.Register(liveAPI, restsurface.Deps{
		IdentityScopes:  []config.ServiceScopes{{Audience: "kubernetes", Scopes: []string{"clusters"}}},
		OIDCIssuerURL:   "https://issuer.example",
		AllowedAPIBases: []string{"https://ghe.example/api/v3"},
	})
	live := operationSet(liveAPI)

	if len(exported) == 0 {
		t.Fatal("exported spec has no operations")
	}
	if len(live) != len(exported) {
		t.Fatalf("operation count drift: exported %d, live %d", len(exported), len(live))
	}
	for i := range live {
		if live[i] != exported[i] {
			t.Fatalf("operation drift at %d: exported %q, live %q", i, exported[i], live[i])
		}
	}
}

// TestExportContainsFullRESTSurface asserts the offline-exported spec covers
// every key module path so inari-api consumers (CLI, TS clients) never see a
// partial contract. The structural guarantee is TestExportParityWithLiveWiring;
// this list is the regression safety net for modules that were historically
// omitted from the exporter.
func TestExportContainsFullRESTSurface(t *testing.T) {
	var buf bytes.Buffer
	if err := run(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("exported spec is empty")
	}
	spec := buf.String()
	paths := []string{
		// Legacy surface (original 12 assertions).
		"/api/v1/tenants",
		"/api/v1/tenants/{org}/clusters",
		"/api/v1/tenants/{org}/catalog",
		"/api/v1/tenants/{org}/instances",
		"/api/v1/tenants/{org}/deploys",
		"/api/v1/tenants/{org}/clusters/{id}/capabilities",
		"/api/v1/tenants/{org}/approvals",
		"/api/v1/tenants/{org}/cloud-accounts",
		"/api/v1/tenants/{org}/notification-endpoints",
		"/api/v1/tenants/{org}/policies",
		"/api/v1/tenants/{org}/zones",
		"/api/v1/admin/catalog/sync",
		// me
		"/api/v1/me/permissions",
		// auditapi
		"/api/v1/tenants/{org}/audit-events",
		"/api/v1/tenants/{org}/audit",
		"/api/v1/tenants/{org}/audit/export",
		// platformresources
		"/api/v1/tenants/{org}/platform-resources",
		"/api/v1/tenants/{org}/platform-resources/{id}",
		"/api/v1/tenants/{org}/platform-resources/reconcile",
		// scaffold (canonical + UI-compat)
		"/api/v1/tenants/{org}/templates",
		"/api/v1/tenants/{org}/templates/{name}",
		"/api/v1/tenants/{org}/templates/{name}/runs",
		"/api/v1/tenants/{org}/scaffold-runs/{runId}",
		"/api/v1/tenants/{org}/scaffold-runs/{runId}/cancel",
		"/api/v1/tenants/{org}/scaffold-runs/{runId}/retry",
		"/api/v1/tenants/{org}/scaffolds",
		"/api/v1/tenants/{org}/scaffolds/{runId}",
		// secretstores
		"/api/v1/tenants/{org}/secret-stores",
		"/api/v1/tenants/{org}/secret-stores/{name}",
		"/api/v1/tenants/{org}/secret-stores/{name}/status",
		// tenancy: rbac + identity brokering + deletion
		"/api/v1/tenants/{org}/rbac",
		"/api/v1/tenants/{org}/rbac/mappings",
		"/api/v1/tenants/{org}/identity/provider",
		"/api/v1/tenants/{org}/identity/providers",
		"/api/v1/tenants/{org}/identity/providers/{alias}",
		"/api/v1/tenants/{org}/identity/scopes",
		"/api/v1/tenants/{org}/deletion",
		"/api/v1/tenants/{org}/deletion/dependencies",
		// clusterregistry access-info + extensionhost ui surface
		"/api/v1/tenants/{org}/clusters/{id}/access-info",
		"/api/v1/tenants/{org}/extensions/ui",
		"/api/v1/tenants/{org}/extensions/ui/{name}",
		"/api/v1/tenants/{org}/authz/self/extensions",
	}
	for _, p := range paths {
		if !strings.Contains(spec, p+":") {
			t.Errorf("spec missing path %s", p)
		}
	}
}
