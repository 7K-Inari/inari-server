// Package restsurface is the single source of truth for the REST route set
// of the inari-server control plane. Both the live binary
// (cmd/inari-server) and the offline OpenAPI exporter (cmd/export-openapi)
// register their huma routes through Register so the two can never drift:
// the published OpenAPI artifact always matches the served surface.
//
// Constructors and route registration never dereference their dependencies
// (they are only touched per-request), so the exporter passes a zero Deps
// and renders the full spec without any infrastructure. A route that must
// not appear in the published spec is marked huma `Hidden: true` on its
// Operation — omitting a module from this registry is never the mechanism
// for hiding routes.
package restsurface

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/auditapi"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/cloudaccounts"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/config"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/extensionhost"
	"github.com/7K-Inari/inari-server/internal/fleetmanager"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/notifications"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/platformresources"
	"github.com/7K-Inari/inari-server/internal/policyservice"
	"github.com/7K-Inari/inari-server/internal/scaffold"
	"github.com/7K-Inari/inari-server/internal/secretstores"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/tenantzonefactory"
)

// Deps carries every dependency the REST handlers need. The live binary
// fills all fields; the OpenAPI exporter passes a zero value (nil services).
// Scalar/config fields (OIDCIssuerURL, IdentityScopes, AllowedAPIBases,
// RemoteEntries) only affect request-time behavior, never the route set.
type Deps struct {
	Tenancy            *tenancy.Service
	Authz              authz.Authorizer
	Clusters           *clusterregistry.Service
	CapabilitiesLister clusterregistry.CapabilitiesLister
	Catalog            *catalog.Service
	Approvals          *approvals.Service
	Inventory          *inventory.Service
	PlatformResources  *platformresources.Service
	Orchestrator       *orchestrator.Service
	CloudAccounts      *cloudaccounts.Service
	Notifications      *notifications.Service
	Policies           *policyservice.Service
	Scaffold           *scaffold.Service
	TenantZones        *tenantzonefactory.Service
	Fleet              *fleetmanager.Service
	SecretStores       *secretstores.Service
	Extensions         *extensionhost.Service
	DB                 *db.DB
	AuditStore         *audit.Store

	IdentityScopes  []config.ServiceScopes
	OIDCIssuerURL   string
	AllowedAPIBases []string
	RemoteEntries   *extensionhost.RemoteEntryFetcher
	// DisableKubectlProxy is the global kubectl-proxy kill switch
	// (config.Config.DisableKubectlProxy / INARI_DISABLE_KUBECTL_PROXY).
	DisableKubectlProxy bool
}

// Register mounts every module's REST routes on the huma API. The call order
// mirrors the historical wiring in cmd/inari-server; huma registration is
// order-independent (routes key on method+path).
func Register(api huma.API, d Deps) {
	tenancy.NewHandler(d.Tenancy, d.Authz).WithScopesCatalog(d.IdentityScopes).RegisterRoutes(api)
	tenancy.NewMeHandler(d.Authz, d.Tenancy).
		WithKubectlProxy(d.DisableKubectlProxy).RegisterRoutes(api)
	clusterregistry.NewHandler(d.Clusters, d.Tenancy, d.Authz, d.CapabilitiesLister).
		WithAccessInfo(d.OIDCIssuerURL).
		WithKubectlProxy(d.DisableKubectlProxy).RegisterRoutes(api)
	catalog.NewHandler(d.Catalog, d.Tenancy, d.Authz).RegisterRoutes(api)
	approvals.NewHandler(d.Approvals, d.Tenancy, d.Authz, d.Tenancy).RegisterRoutes(api)
	inventory.NewHandler(d.Inventory, d.Tenancy, d.Authz).RegisterRoutes(api)
	platformresources.NewHandler(d.PlatformResources, d.Tenancy, d.Authz).RegisterRoutes(api)
	orchestrator.NewHandler(d.Orchestrator, d.Tenancy, d.Authz).
		WithAllowedAPIBases(d.AllowedAPIBases).RegisterRoutes(api)
	cloudaccounts.NewHandler(d.CloudAccounts, d.Tenancy, d.Clusters, d.Authz).RegisterRoutes(api)
	notifications.NewHandler(d.Notifications, d.Tenancy, d.Authz).RegisterRoutes(api)
	policyservice.NewHandler(d.Policies, d.Tenancy, d.Authz).RegisterRoutes(api)
	scaffold.NewHandler(d.Scaffold, d.Tenancy, d.Authz).RegisterRoutes(api)
	tenantzonefactory.NewHandler(d.TenantZones, d.Tenancy, d.Authz).RegisterRoutes(api)
	fleetmanager.NewHandler(d.Fleet, d.Tenancy, d.Authz).RegisterRoutes(api)
	secretstores.NewHandler(d.SecretStores, d.Tenancy, d.Authz).RegisterRoutes(api)
	extensionhost.NewHandler(d.Extensions, d.Tenancy, d.Authz).
		WithRemoteEntryFetcher(d.RemoteEntries).RegisterRoutes(api)
	auditapi.NewHandler(d.DB, d.AuditStore, d.Tenancy, d.Authz).RegisterRoutes(api)
}
