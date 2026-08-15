// HTTP handlers for the inventory module (plan §5.2 Resources Inventory).
package inventory

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

// Handler exposes the inventory REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the inventory API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "listInstances",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/instances",
		Summary:     "List resource instances (filterable by cluster, item, health, owner team)",
		Security:    httpserver.SecurityRequirement(),
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID: "getInstance",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/instances/{id}",
		Summary:     "Get one resource instance with version badge",
		Security:    httpserver.SecurityRequirement(),
	}, h.get)
}

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

type listInput struct {
	Org       string `path:"org"`
	Cluster   string `query:"cluster"`
	Item      string `query:"item"`
	Health    string `query:"health"`
	OwnerTeam string `query:"ownerTeam"`
}

type listOutput struct {
	Body struct {
		Instances []InstanceView `json:"instances"`
	}
}

func (h *Handler) list(ctx context.Context, in *listInput) (*listOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	instances, err := h.svc.List(ctx, org.ID, ListFilters{
		ClusterID: in.Cluster, ItemID: in.Item, Health: in.Health, OwnerTeam: in.OwnerTeam,
	})
	if err != nil {
		return nil, err
	}
	out := &listOutput{}
	out.Body.Instances = instances
	return out, nil
}

type getInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

type getOutput struct {
	Body struct {
		Instance InstanceView `json:"instance"`
	}
}

func (h *Handler) get(ctx context.Context, in *getInput) (*getOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	inst, err := h.svc.Get(ctx, org.ID, in.ID)
	if errors.Is(err, ErrInstanceNotFound) {
		return nil, huma.Error404NotFound("instance not found")
	}
	if err != nil {
		return nil, err
	}
	out := &getOutput{}
	out.Body.Instance = *inst
	return out, nil
}
