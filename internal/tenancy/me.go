package tenancy

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/types"
)

// MeHandler exposes the caller's platform-level permission surface (M1.W2),
// backed by OpenFGA checks. The response is a flat struct so new flags are
// additive, non-breaking changes.
type MeHandler struct {
	authz   authz.Authorizer
	tenants MeTenantResolver
}

// MeTenantResolver resolves a tenant slug to its record (tenancy.Service).
type MeTenantResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

func NewMeHandler(az authz.Authorizer, tenants MeTenantResolver) *MeHandler {
	return &MeHandler{authz: az, tenants: tenants}
}

func (h *MeHandler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "getMyPermissions",
		Method:      http.MethodGet,
		Path:        "/api/v1/me/permissions",
		Summary:     "Platform-level permissions of the authenticated caller",
		Security:    httpserver.SecurityRequirement(),
	}, h.getMyPermissions)
}

type myPermissionsOutput struct {
	Body struct {
		CanCreateOrganizations bool `json:"canCreateOrganizations" doc:"Caller may create tenants (platform:inari org_creator)"`
		// OrgRoles maps every organization the caller belongs to (slug) to
		// its effective role, using the same role strings as the members API
		// ("org-admin", "platform-engineer", "developer", "viewer"). The
		// console derives its write-enablement from this; without it the UI
		// can only guess from the token and falls back to read-only
		// (live incident 2026-09-16).
		OrgRoles map[string]types.Role `json:"orgRoles,omitempty"`
		// Tenants maps every organization the caller belongs to (slug) to
		// its capability projection, derived from the same FGA relations as
		// OrgRoles in a single pass (RBAC redesign Phase A). The access
		// console gates individual actions on these flags instead of the
		// binary admin/viewer split.
		Tenants map[string]TenantCapabilities `json:"tenants,omitempty"`
	}
}

// TenantCapabilities is the per-tenant action projection the access console
// disables/enables on. Flags mirror the REST route gates:
// canDeploy=developer+ (orchestrator deploys), canManageMembers=
// platform-engineer+ (team member add/remove), canManageTeams and
// canManageRbac=org-admin (team CRUD, rbac/mappings).
type TenantCapabilities struct {
	CanDeploy        bool `json:"canDeploy"`
	CanManageMembers bool `json:"canManageMembers"`
	CanManageTeams   bool `json:"canManageTeams"`
	CanManageRbac    bool `json:"canManageRbac"`
}

func (h *MeHandler) getMyPermissions(ctx context.Context, _ *struct{}) (*myPermissionsOutput, error) {
	id := identity(ctx)
	if id == nil {
		return nil, huma.Error401Unauthorized("unauthenticated")
	}
	ok, err := h.authz.Check(ctx, authz.UserObject(id.Subject), authz.RelationOrgCreator, authz.ObjectPlatform)
	if err != nil {
		return nil, err
	}
	out := &myPermissionsOutput{}
	out.Body.CanCreateOrganizations = ok
	if h.tenants != nil && len(id.Organizations) > 0 {
		out.Body.OrgRoles = map[string]types.Role{}
		out.Body.Tenants = map[string]TenantCapabilities{}
		for _, slug := range id.Organizations {
			role, caps, err := h.effectiveAccess(ctx, id.Subject, slug)
			if err != nil {
				return nil, err
			}
			if role != "" {
				out.Body.OrgRoles[slug] = role
				out.Body.Tenants[slug] = caps
			}
		}
	}
	return out, nil
}

// effectiveAccess reports the caller's strongest role in one org and the
// capability set that role grants, in a single strongest-first pass:
// admin ⊇ platform_engineer ⊇ developer ⊇ viewer (model.fga hierarchy), so
// the first passing relation determines the whole projection.
func (h *MeHandler) effectiveAccess(ctx context.Context, subject, slug string) (types.Role, TenantCapabilities, error) {
	org, err := h.tenants.GetTenant(ctx, slug)
	if err != nil {
		return "", TenantCapabilities{}, err
	}
	user := authz.UserObject(subject)
	obj := authz.OrgObject(org.ID)
	for _, step := range []struct {
		relation string
		role     types.Role
		caps     TenantCapabilities
	}{
		{authz.RelationAdmin, types.RoleOrgAdmin, TenantCapabilities{
			CanDeploy: true, CanManageMembers: true, CanManageTeams: true, CanManageRbac: true,
		}},
		{authz.RelationPlatformEngineer, types.RolePlatformEngineer, TenantCapabilities{
			CanDeploy: true, CanManageMembers: true,
		}},
		{authz.RelationDeveloper, types.RoleDeveloper, TenantCapabilities{
			CanDeploy: true,
		}},
		{authz.RelationViewer, types.RoleViewer, TenantCapabilities{}},
	} {
		ok, err := h.authz.Check(ctx, user, step.relation, obj)
		if err != nil {
			return "", TenantCapabilities{}, err
		}
		if ok {
			return step.role, step.caps, nil
		}
	}
	return "", TenantCapabilities{}, nil
}
