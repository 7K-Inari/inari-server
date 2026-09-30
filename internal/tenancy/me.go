package tenancy

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/types"
)

// MeHandler exposes the caller's platform-level permission surface (M1.W2),
// backed by OpenFGA permission checks plus the DB membership→roles
// projection. The response is a flat struct so new flags are additive,
// non-breaking changes.
type MeHandler struct {
	authz   authz.Authorizer
	tenants MeTenantResolver
	members MeMembershipResolver
}

// MeTenantResolver resolves a tenant slug to its record (tenancy.Service).
type MeTenantResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

// MeMembershipResolver lists the caller's role names in one org from the DB
// membership projection (tenancy.Service seam, ADR-0013).
type MeMembershipResolver interface {
	ListMemberRoleNames(ctx context.Context, orgID, userID string) ([]string, error)
}

func NewMeHandler(az authz.Authorizer, tenants MeTenantResolver, members MeMembershipResolver) *MeHandler {
	return &MeHandler{authz: az, tenants: tenants, members: members}
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
		// Roles maps every organization the caller belongs to (slug) to the
		// role names they hold there (DB memberships → roles; custom roles
		// have no total order, so this is a set, replacing the retired
		// single "effective role" string — ADR-0013).
		Roles map[string][]string `json:"roles,omitempty"`
		// Tenants maps every organization the caller belongs to (slug) to
		// its capability projection, derived from FGA permission checks.
		// The access console gates individual actions on these flags
		// instead of the binary admin/viewer split.
		Tenants map[string]TenantCapabilities `json:"tenants,omitempty"`
	}
}

// TenantCapabilities is the per-tenant action projection the access console
// disables/enables on. Flags map 1:1 onto permission-catalog slugs:
// canDeploy=deployments.create, canManageMembers=tenant.members.manage,
// canManageTeams=tenant.teams.manage, canManageRbac=tenant.rbac.manage.
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
	if h.tenants != nil && h.members != nil && len(id.Organizations) > 0 {
		out.Body.Roles = map[string][]string{}
		out.Body.Tenants = map[string]TenantCapabilities{}
		for _, slug := range id.Organizations {
			roles, caps, err := h.effectiveAccess(ctx, id.Subject, slug)
			if errors.Is(err, ErrOrgNotFound) {
				// Stale claim (e.g. a deleted tenant still in the token):
				// skip it instead of failing the whole projection.
				continue
			}
			if err != nil {
				return nil, err
			}
			if len(roles) > 0 {
				out.Body.Roles[slug] = roles
				out.Body.Tenants[slug] = caps
			}
		}
	}
	return out, nil
}

// effectiveAccess reports the caller's role names in one org (DB
// projection) and the capability set their permissions grant (one FGA check
// per capability flag).
func (h *MeHandler) effectiveAccess(ctx context.Context, subject, slug string) ([]string, TenantCapabilities, error) {
	org, err := h.tenants.GetTenant(ctx, slug)
	if err != nil {
		return nil, TenantCapabilities{}, err
	}
	roles, err := h.members.ListMemberRoleNames(ctx, org.ID, subject)
	if err != nil {
		return nil, TenantCapabilities{}, err
	}
	if len(roles) == 0 {
		return nil, TenantCapabilities{}, nil
	}
	user := authz.UserObject(subject)
	obj := authz.OrgObject(org.ID)
	var caps TenantCapabilities
	for _, step := range []struct {
		relation string
		set      func()
	}{
		{authz.RelationDeploymentsCreate, func() { caps.CanDeploy = true }},
		{authz.RelationTenantMembersManage, func() { caps.CanManageMembers = true }},
		{authz.RelationTenantTeamsManage, func() { caps.CanManageTeams = true }},
		{authz.RelationTenantRBACManage, func() { caps.CanManageRbac = true }},
	} {
		ok, err := h.authz.Check(ctx, user, step.relation, obj)
		if err != nil {
			return nil, TenantCapabilities{}, err
		}
		if ok {
			step.set()
		}
	}
	return roles, caps, nil
}
