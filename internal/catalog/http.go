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
		OperationID: "listCatalogVisibility",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/catalog-visibility",
		Summary:     "List effective catalog visibility for the tenant (platform rule AND org overlay)",
		Security:    httpserver.SecurityRequirement(),
	}, h.listOrgVisibility)

	huma.Register(api, huma.Operation{
		OperationID: "setCatalogOrgVisibility",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/catalog-visibility/{item}",
		Summary:     "Set the org-level visibility overlay for one catalog item (org admin)",
		Security:    httpserver.SecurityRequirement(),
	}, h.setOrgVisibility)

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
		Summary:     "Sync trusted catalog sources independently (platform engineer)",
		Security:    httpserver.SecurityRequirement(),
	}, h.syncCatalog)
	huma.Register(api, huma.Operation{
		OperationID: "listCatalogSources",
		Method:      http.MethodGet,
		Path:        "/api/v1/admin/catalog/sources",
		Summary:     "List catalog source health and last-good snapshots (platform engineer)",
		Security:    httpserver.SecurityRequirement(),
	}, h.listCatalogSources)
	huma.Register(api, huma.Operation{
		OperationID: "listTemplateSources",
		Method:      http.MethodGet,
		Path:        "/api/v1/admin/templates/sources",
		Summary:     "List template source health and last-good snapshots (platform engineer)",
		Security:    httpserver.SecurityRequirement(),
	}, h.listTemplateSources)
	huma.Register(api, huma.Operation{
		OperationID: "syncTemplates",
		Method:      http.MethodPost,
		Path:        "/api/v1/admin/templates/sync",
		Summary:     "Sync trusted template sources independently (platform engineer)",
		Security:    httpserver.SecurityRequirement(),
	}, h.syncTemplates)
	huma.Register(api, huma.Operation{
		OperationID: "getSourceCatalogItem",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/catalog/{source}/{name}",
		Summary:     "Get a source-qualified catalog item",
		Security:    httpserver.SecurityRequirement(),
	}, h.getSourceItem)
	huma.Register(api, huma.Operation{
		OperationID: "pinSourceCatalogVersion",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/catalog/{source}/{name}/pin",
		Summary:     "Pin a source-qualified catalog item version",
		Security:    httpserver.SecurityRequirement(),
	}, h.setSourcePin)
	huma.Register(api, huma.Operation{
		OperationID: "unpinSourceCatalogVersion",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/catalog/{source}/{name}/pin",
		Summary:     "Remove a source-qualified version pin",
		Security:    httpserver.SecurityRequirement(),
	}, h.deleteSourcePin)
	huma.Register(api, huma.Operation{
		OperationID: "setSourceCatalogOrgVisibility",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/catalog-visibility/{source}/{name}",
		Summary:     "Set org visibility for a source-qualified item",
		Security:    httpserver.SecurityRequirement(),
	}, h.setSourceOrgVisibility)
	huma.Register(api, huma.Operation{
		OperationID: "setSourceCatalogVisibility",
		Method:      http.MethodPut,
		Path:        "/api/v1/admin/catalog/{source}/{name}/visibility",
		Summary:     "Set visibility for a source-qualified item (platform engineer)",
		Security:    httpserver.SecurityRequirement(),
	}, h.setSourceVisibility)
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
	ok, err := h.authz.Check(ctx, authz.UserObject(id.Subject), authz.RelationClustersRegister, authz.OrgObject(org.ID))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, huma.Error403Forbidden("platform engineer role required")
	}
	return id, nil
}

type listCatalogInput struct {
	Org       string `path:"org"`
	Cluster   string `query:"cluster" doc:"Cluster ID; intersects discovered capabilities"`
	Query     string `query:"q" doc:"Free-text search over name, display name, and description"`
	Source    string `query:"source" enum:"curated,discovered,platform,template" doc:"Filter by item kind"`
	SourceID  string `query:"sourceId" doc:"Filter by server-assigned source ID"`
	TrustTier string `query:"trustTier" enum:"official,reviewed,experimental" doc:"Filter by source trust tier"`
	Category  string `query:"category" doc:"Filter by package category (discovered projections have no category)"`
	Sort      string `query:"sort" enum:"name,name-desc,newest,oldest" default:"name" doc:"Sort order (whitelisted server-side)"`
	Limit     int    `query:"limit" minimum:"0" maximum:"200" doc:"Page size; 0 returns all matches"`
	Offset    int    `query:"offset" minimum:"0" doc:"Page offset into the filtered, sorted result"`
}

type listCatalogOutput struct {
	Body struct {
		Items []ItemView `json:"items"`
		Total int        `json:"total"`
	}
}

func (h *Handler) listCatalog(ctx context.Context, in *listCatalogInput) (*listCatalogOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	items, total, err := h.svc.ListVisible(ctx, org.ID, types.CatalogListOptions{
		Query:     in.Query,
		Source:    in.Source,
		SourceID:  in.SourceID,
		TrustTier: in.TrustTier,
		Category:  in.Category,
		ClusterID: in.Cluster,
		Sort:      in.Sort,
		Limit:     in.Limit,
		Offset:    in.Offset,
	})
	if err != nil {
		return nil, err
	}
	out := &listCatalogOutput{}
	out.Body.Items = items
	out.Body.Total = total
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
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
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
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationCatalogManage)
	if err != nil {
		return nil, err
	}
	if err := h.svc.SetPin(ctx, "user:"+id.Subject, org.ID, in.Item, in.Body.Version); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	return nil, nil
}

func (h *Handler) deletePin(ctx context.Context, in *itemPathInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationCatalogManage)
	if err != nil {
		return nil, err
	}
	return nil, h.svc.DeletePin(ctx, "user:"+id.Subject, org.ID, in.Item)
}

type listOrgVisibilityInput struct {
	Org string `path:"org"`
}

type listOrgVisibilityOutput struct {
	Body struct {
		Items []OrgVisibilityEntry `json:"items"`
	}
}

func (h *Handler) listOrgVisibility(ctx context.Context, in *listOrgVisibilityInput) (*listOrgVisibilityOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	items, err := h.svc.ListOrgVisibility(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listOrgVisibilityOutput{}
	out.Body.Items = items
	return out, nil
}

type orgVisibilityInput struct {
	Org  string `path:"org"`
	Item string `path:"item"`
	Body struct {
		Visible bool `json:"visible" doc:"false hides the item for this org; true shows it (subject to platform rules)"`
	}
}

func (h *Handler) setOrgVisibility(ctx context.Context, in *orgVisibilityInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantAdmin)
	if err != nil {
		return nil, err
	}
	err = h.svc.SetOrgVisibility(ctx, "user:"+id.Subject, org.ID, in.Item, in.Body.Visible)
	if errors.Is(err, ErrItemNotFound) {
		return nil, huma.Error404NotFound("catalog item not found")
	}
	return nil, err
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
		Synced  int                         `json:"synced"`
		Sources []types.TrustedSourceStatus `json:"sources"`
	}
}

func (h *Handler) syncCatalog(ctx context.Context, _ *struct{}) (*syncOutput, error) {
	return h.syncKind(ctx, "catalog")
}

func (h *Handler) syncTemplates(ctx context.Context, _ *struct{}) (*syncOutput, error) {
	return h.syncKind(ctx, "template")
}

func (h *Handler) syncKind(ctx context.Context, kind string) (*syncOutput, error) {
	if _, err := h.authorizePlatform(ctx); err != nil {
		return nil, err
	}
	n, syncErr := h.svc.SyncKind(ctx, kind)
	if errors.Is(syncErr, ErrSyncNotConfigured) {
		return nil, huma.Error409Conflict(syncErr.Error())
	}
	states, err := h.svc.ListTrustedSourceStates(ctx, kind)
	if err != nil {
		return nil, err
	}
	out := &syncOutput{}
	out.Body.Synced = n
	out.Body.Sources = states
	// A source failure is represented in its own status. It must not hide
	// successful independent sources or their last-good snapshots.
	return out, nil
}

type sourceListOutput struct {
	Body struct {
		Sources []types.TrustedSourceStatus `json:"sources"`
	}
}

func (h *Handler) listCatalogSources(ctx context.Context, _ *struct{}) (*sourceListOutput, error) {
	return h.listSources(ctx, "catalog")
}

func (h *Handler) listTemplateSources(ctx context.Context, _ *struct{}) (*sourceListOutput, error) {
	return h.listSources(ctx, "template")
}

func (h *Handler) listSources(ctx context.Context, kind string) (*sourceListOutput, error) {
	if _, err := h.authorizePlatform(ctx); err != nil {
		return nil, err
	}
	states, err := h.svc.ListTrustedSourceStates(ctx, kind)
	if err != nil {
		return nil, err
	}
	out := &sourceListOutput{}
	out.Body.Sources = states
	return out, nil
}

type sourceItemPathInput struct {
	Org     string `path:"org"`
	Source  string `path:"source"`
	Name    string `path:"name"`
	Cluster string `query:"cluster"`
}

func (h *Handler) getSourceItem(ctx context.Context, in *sourceItemPathInput) (*itemOutput, error) {
	return h.getItem(ctx, &itemPathInput{Org: in.Org, Item: in.Source + "/" + in.Name, Cluster: in.Cluster})
}

type sourcePinInput struct {
	sourceItemPathInput
	Body struct {
		Version string `json:"version" minLength:"1"`
	}
}

func (h *Handler) setSourcePin(ctx context.Context, in *sourcePinInput) (*struct{}, error) {
	return h.setPin(ctx, &pinInput{Org: in.Org, Item: in.Source + "/" + in.Name, Body: in.Body})
}

func (h *Handler) deleteSourcePin(ctx context.Context, in *sourceItemPathInput) (*struct{}, error) {
	return h.deletePin(ctx, &itemPathInput{Org: in.Org, Item: in.Source + "/" + in.Name})
}

type sourceOrgVisibilityInput struct {
	sourceItemPathInput
	Body struct {
		Visible bool `json:"visible" doc:"false hides the item for this org; true shows it (subject to platform rules)"`
	}
}

func (h *Handler) setSourceOrgVisibility(ctx context.Context, in *sourceOrgVisibilityInput) (*struct{}, error) {
	return h.setOrgVisibility(ctx, &orgVisibilityInput{Org: in.Org, Item: in.Source + "/" + in.Name, Body: in.Body})
}

type sourceVisibilityInput struct {
	sourceItemPathInput
	Body struct {
		Rules []struct {
			OrgID     string `json:"orgId" minLength:"1"`
			ClusterID string `json:"clusterId,omitempty"`
		} `json:"rules"`
	}
}

func (h *Handler) setSourceVisibility(ctx context.Context, in *sourceVisibilityInput) (*struct{}, error) {
	return h.setVisibility(ctx, &visibilityInput{Item: in.Source + "/" + in.Name, Body: in.Body})
}
