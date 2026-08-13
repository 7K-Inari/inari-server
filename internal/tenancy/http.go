// HTTP handlers for the tenancy module.
package tenancy

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Handler exposes the tenancy REST surface.
type Handler struct {
	svc   *Service
	authz authz.Authorizer
}

func NewHandler(svc *Service, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, authz: az}
}

// RegisterRoutes mounts the tenancy API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "createTenant",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants",
		Summary:     "Create a tenant (Keycloak Organization + default teams)",
		Security:    httpserver.SecurityRequirement(),
	}, h.createTenant)

	huma.Register(api, huma.Operation{
		OperationID: "listTenants",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants",
		Summary:     "List tenants visible to the caller (tenant switcher)",
		Security:    httpserver.SecurityRequirement(),
	}, h.listTenants)

	huma.Register(api, huma.Operation{
		OperationID: "getTenant",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}",
		Summary:     "Get a tenant by slug",
		Security:    httpserver.SecurityRequirement(),
	}, h.getTenant)

	huma.Register(api, huma.Operation{
		OperationID: "listTeams",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/teams",
		Summary:     "List teams of a tenant",
		Security:    httpserver.SecurityRequirement(),
	}, h.listTeams)
}

type createTenantInput struct {
	Body struct {
		Slug        string `json:"slug" minLength:"2" maxLength:"63" pattern:"^[a-z0-9][a-z0-9-]*$" doc:"URL-safe tenant slug"`
		DisplayName string `json:"displayName" minLength:"1" maxLength:"200"`
	}
}

type tenantOutput struct {
	Body struct {
		Organization types.Organization `json:"organization"`
		Teams        []types.Team       `json:"teams"`
	}
}

func (h *Handler) createTenant(ctx context.Context, in *createTenantInput) (*tenantOutput, error) {
	id := identity(ctx)
	if id == nil {
		return nil, huma.Error401Unauthorized("unauthenticated")
	}
	org, teams, err := h.svc.CreateTenant(ctx, id.Subject, in.Body.Slug, in.Body.DisplayName)
	if errors.Is(err, ErrSlugTaken) {
		return nil, huma.Error409Conflict("tenant slug already exists")
	}
	if err != nil {
		return nil, err
	}
	out := &tenantOutput{}
	out.Body.Organization = *org
	out.Body.Teams = teams
	return out, nil
}

type listTenantsOutput struct {
	Body struct {
		Tenants []types.Organization `json:"tenants"`
	}
}

func (h *Handler) listTenants(ctx context.Context, _ *struct{}) (*listTenantsOutput, error) {
	id := identity(ctx)
	if id == nil {
		return nil, huma.Error401Unauthorized("unauthenticated")
	}
	// Fine PEP: objects the caller may view per OpenFGA.
	allowed, err := h.authz.ListObjects(ctx, authz.UserObject(id.Subject), authz.RelationViewer, authz.TypeOrganization)
	if err != nil {
		return nil, err
	}
	allowedSet := map[string]bool{}
	for _, o := range allowed {
		allowedSet[o] = true
	}
	all, err := h.svc.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	out := &listTenantsOutput{}
	for _, org := range all {
		// Authorize by claim AND relationship store.
		if id.MemberOf(org.Slug) && allowedSet[authz.OrgObject(org.ID)] {
			out.Body.Tenants = append(out.Body.Tenants, org)
		}
	}
	return out, nil
}

type orgPathInput struct {
	Org string `path:"org" doc:"Tenant slug"`
}

func (h *Handler) getTenant(ctx context.Context, in *orgPathInput) (*tenantOutput, error) {
	org, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	teams, err := h.svc.ListTeams(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &tenantOutput{}
	out.Body.Organization = *org
	out.Body.Teams = teams
	return out, nil
}

type listTeamsOutput struct {
	Body struct {
		Teams []types.Team `json:"teams"`
	}
}

func (h *Handler) listTeams(ctx context.Context, in *orgPathInput) (*listTeamsOutput, error) {
	org, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	teams, err := h.svc.ListTeams(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listTeamsOutput{}
	out.Body.Teams = teams
	return out, nil
}

// authorizeOrg performs coarse PEP (org claim) + fine PEP (OpenFGA Check).
func (h *Handler) authorizeOrg(ctx context.Context, slug, relation string) (*types.Organization, error) {
	id := identity(ctx)
	if id == nil {
		return nil, huma.Error401Unauthorized("unauthenticated")
	}
	// Coarse PEP: tenant comes from the token claim, never the URL alone.
	if !id.MemberOf(slug) {
		return nil, huma.Error403Forbidden("not a member of this organization")
	}
	org, err := h.svc.GetTenant(ctx, slug)
	if errors.Is(err, ErrOrgNotFound) {
		return nil, huma.Error404NotFound("organization not found")
	}
	if err != nil {
		return nil, err
	}
	ok, err := h.authz.Check(ctx, authz.UserObject(id.Subject), relation, authz.OrgObject(org.ID))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, huma.Error403Forbidden("insufficient permissions")
	}
	return org, nil
}

func identity(ctx context.Context) *authn.Identity {
	return httpserver.IdentityFromContext(ctx)
}
