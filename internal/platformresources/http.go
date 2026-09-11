// HTTP handlers for the platform resources module (plan §5.2, M7).
package platformresources

import (
	"context"
	"errors"
	"net/http"
	"time"

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

// Handler exposes the platform resources REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the platform resources API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "listPlatformResources",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/platform-resources",
		Summary:     "List tenant platform resources (keycloak realm/client, dns zone, namespace)",
		Security:    httpserver.SecurityRequirement(),
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID: "getPlatformResource",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/platform-resources/{id}",
		Summary:     "Get one tenant platform resource",
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

// resourceView is the console shape (inari-ui src/api/platform.ts).
type resourceView struct {
	ID        string                       `json:"id"`
	Tenant    string                       `json:"tenant"`
	Kind      types.PlatformResourceKind   `json:"kind"`
	Name      string                       `json:"name"`
	Status    types.PlatformResourceStatus `json:"status"`
	Detail    string                       `json:"detail"`
	UpdatedAt time.Time                    `json:"updatedAt"`
}

func toView(r *types.PlatformResource) resourceView {
	return resourceView{
		ID: r.ID, Tenant: r.OrgID, Kind: r.Kind, Name: r.Name,
		Status: r.Status, Detail: r.Detail, UpdatedAt: r.UpdatedAt,
	}
}

type listInput struct {
	Org string `path:"org"`
}

type listOutput struct {
	Body struct {
		Resources []resourceView `json:"resources"`
	}
}

func (h *Handler) list(ctx context.Context, in *listInput) (*listOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	resources, err := h.svc.List(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listOutput{}
	out.Body.Resources = make([]resourceView, 0, len(resources))
	for i := range resources {
		out.Body.Resources = append(out.Body.Resources, toView(&resources[i]))
	}
	return out, nil
}

type getInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

type getOutput struct {
	Body struct {
		Resource resourceView `json:"resource"`
	}
}

func (h *Handler) get(ctx context.Context, in *getInput) (*getOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Get(ctx, org.ID, in.ID)
	if errors.Is(err, ErrResourceNotFound) {
		return nil, huma.Error404NotFound("platform resource not found")
	}
	if err != nil {
		return nil, err
	}
	out := &getOutput{}
	out.Body.Resource = toView(r)
	return out, nil
}
