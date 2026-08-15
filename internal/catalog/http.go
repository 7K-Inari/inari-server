// HTTP handlers for the catalog module (plan §5.5).
package catalog

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TenantResolver resolves a tenant slug to its record (tenancy.Service).
type TenantResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

// Handler exposes the catalog REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the catalog API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "listCatalog",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/catalog",
		Summary:     "List catalog items visible to the tenant (optionally per cluster)",
		Security:    httpserver.SecurityRequirement(),
	}, h.listCatalog)

	huma.Register(api, huma.Operation{
		OperationID: "getCatalogItem",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/catalog/{item}",
		Summary:     "Get a catalog item with schema, UI hints, and versions",
		Security:    httpserver.SecurityRequirement(),
	}, h.getItem)

	huma.Register(api, huma.Operation{
		OperationID: "pinCatalogVersion",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/catalog/{item}/pin",
		Summary:     "Pin the tenant to a catalog item version",
		Security:    httpserver.SecurityRequirement(),
	}, h.setPin)

	huma.Register(api, huma.Operation{
		OperationID: "unpinCatalogVersion",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/catalog/{item}/pin",
		Summary:     "Remove the tenant's version pin",
		Security:    httpserver.SecurityRequirement(),
	}, h.deletePin)

	huma.Register(api, huma.Operation{
		OperationID: "setCatalogVisibility",
		Method:      http.MethodPut,
		Path:        "/api/v1/admin/catalog/{item}/visibility",
		Summary:     "Set per-tenant/cluster visibility rules (platform engineer)",
		Security:    httpserver.SecurityRequirement(),
	}, h.setVisibility)

	huma.Register(api, huma.Operation{
		OperationID: "syncCatalog",
		Method:      http.MethodPost,
		Path:        "/api/v1/admin/catalog/sync",
		Summary:     "Sync curated packages from the catalog registry (platform engineer)",
		Security:    httpserver.SecurityRequirement(),
	}, h.syncCatalog)
}

// authorizeOrg performs coarse PEP (org claim) + fine PEP (OpenFGA Check).
func (h *Handler) authorizeOrg(ctx context.Context, slug, relation string) (*types.Organization, *authn.Identity, error) {
	id := httpserver.IdentityFromContext(ctx)
	if id == nil {
		return nil, nil, huma.Error401Unauthorized("unauthenticated")
	}
	if !id.MemberOf(slug) {
		return nil, nil, huma.Error403Forbidden("not a member of this organization")
	}
	org, err := h.tenants.GetTenant(ctx, slug)
	if errors.Is(err, tenancy.ErrOrgNotFound) {
		return nil, nil, huma.Error404NotFound("organization not found")
	}
	if err != nil {
		return nil, nil, err
	}
	ok, err := h.authz.Check(ctx, authz.UserObject(id.Subject), relation, authz.OrgObject(org.ID))
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, huma.Error403Forbidden("insufficient permissions")
	}
	return org, id, nil
}

// authorizePlatform gates admin endpoints: any org the caller belongs to
// where they hold platform_engineer. M2 simplification: the caller must be a
// platform engineer of their first org (the platform org).
func (h *Handler) authorizePlatform(ctx context.Context) (*authn.Identity, error) {
	id := httpserver.IdentityFromContext(ctx)
	if id == nil {
		return nil, huma.Error401Unauthorized("unauthenticated")
	}
	if len(id.Organizations) == 0 {
		return nil, huma.Error403Forbidden("no organization membership")
	}
	org, err := h.tenants.GetTenant(ctx, id.Organizations[0])
	if err != nil {
		return nil, huma.Error403Forbidden("platform organization not found")
	}
	ok, err := h.authz.Check(ctx, authz.UserObject(id.Subject), authz.RelationPlatformEngineer, authz.OrgObject(org.ID))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, huma.Error403Forbidden("platform engineer role required")
	}
	return id, nil
}

type listCatalogInput struct {
	Org     string `path:"org"`
	Cluster string `query:"cluster" doc:"Cluster ID; intersects discovered capabilities"`
}

type listCatalogOutput struct {
	Body struct {
		Items []ItemView `json:"items"`
	}
}

func (h *Handler) listCatalog(ctx context.Context, in *listCatalogInput) (*listCatalogOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	items, err := h.svc.ListVisible(ctx, org.ID, in.Cluster)
	if err != nil {
		return nil, err
	}
	out := &listCatalogOutput{}
	out.Body.Items = items
	return out, nil
}

type itemPathInput struct {
	Org     string `path:"org"`
	Item    string `path:"item"`
	Cluster string `query:"cluster"`
}

type itemOutput struct {
	Body struct {
		Item ItemView `json:"item"`
	}
}

func (h *Handler) getItem(ctx context.Context, in *itemPathInput) (*itemOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	item, err := h.svc.GetItem(ctx, org.ID, in.Cluster, in.Item)
	if errors.Is(err, ErrItemNotFound) {
		return nil, huma.Error404NotFound("catalog item not found")
	}
	if err != nil {
		return nil, err
	}
	out := &itemOutput{}
	out.Body.Item = *item
	return out, nil
}

type pinInput struct {
	Org  string `path:"org"`
	Item string `path:"item"`
	Body struct {
		Version string `json:"version" minLength:"1"`
	}
}

func (h *Handler) setPin(ctx context.Context, in *pinInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeveloper)
	if err != nil {
		return nil, err
	}
	if err := h.svc.SetPin(ctx, "user:"+id.Subject, org.ID, in.Item, in.Body.Version); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	return nil, nil
}

func (h *Handler) deletePin(ctx context.Context, in *itemPathInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeveloper)
	if err != nil {
		return nil, err
	}
	return nil, h.svc.DeletePin(ctx, "user:"+id.Subject, org.ID, in.Item)
}

type visibilityInput struct {
	Item string `path:"item"`
	Body struct {
		Rules []struct {
			OrgID     string `json:"orgId" minLength:"1"`
			ClusterID string `json:"clusterId,omitempty"`
		} `json:"rules"`
	}
}

func (h *Handler) setVisibility(ctx context.Context, in *visibilityInput) (*struct{}, error) {
	id, err := h.authorizePlatform(ctx)
	if err != nil {
		return nil, err
	}
	rules := make([]types.VisibilityRule, 0, len(in.Body.Rules))
	for _, r := range in.Body.Rules {
		rules = append(rules, types.VisibilityRule{ItemID: in.Item, OrgID: r.OrgID, ClusterID: r.ClusterID})
	}
	return nil, h.svc.SetVisibility(ctx, "user:"+id.Subject, rules)
}

type syncOutput struct {
	Body struct {
		Synced int `json:"synced"`
	}
}

func (h *Handler) syncCatalog(ctx context.Context, _ *struct{}) (*syncOutput, error) {
	if _, err := h.authorizePlatform(ctx); err != nil {
		return nil, err
	}
	n, err := h.svc.Sync(ctx)
	if errors.Is(err, ErrSyncNotConfigured) {
		return nil, huma.Error409Conflict(err.Error())
	}
	if err != nil {
		return nil, err
	}
	out := &syncOutput{}
	out.Body.Synced = n
	return out, nil
}
