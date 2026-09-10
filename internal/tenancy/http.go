// HTTP handlers for the tenancy module.
package tenancy

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/config"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Handler exposes the tenancy REST surface.
type Handler struct {
	svc    *Service
	authz  authz.Authorizer
	scopes []config.ServiceScopes
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
		OperationID: "updateTenant",
		Method:      http.MethodPatch,
		Path:        "/api/v1/tenants/{org}",
		Summary:     "Update the tenant profile (org admin only)",
		Security:    httpserver.SecurityRequirement(),
	}, h.updateTenant)

	huma.Register(api, huma.Operation{
		OperationID: "listTeams",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/teams",
		Summary:     "List teams of a tenant",
		Security:    httpserver.SecurityRequirement(),
	}, h.listTeams)

	huma.Register(api, huma.Operation{
		OperationID: "createTeam",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/teams",
		Summary:     "Create a team granting an org role (org admin only)",
		Security:    httpserver.SecurityRequirement(),
	}, h.createTeam)

	huma.Register(api, huma.Operation{
		OperationID: "deleteTeam",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/teams/{team}",
		Summary:     "Delete a team (org admin only; default teams are protected)",
		Security:    httpserver.SecurityRequirement(),
	}, h.deleteTeam)

	huma.Register(api, huma.Operation{
		OperationID: "listOrgMembers",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/members",
		Summary:     "Org-wide member view (highest role + teams)",
		Security:    httpserver.SecurityRequirement(),
	}, h.listOrgMembers)

	huma.Register(api, huma.Operation{
		OperationID: "setMemberRole",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/members/{subject}",
		Summary:     "Set a user's org role (org admin only)",
		Security:    httpserver.SecurityRequirement(),
	}, h.putMember)

	huma.Register(api, huma.Operation{
		OperationID: "removeOrgMember",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/members/{subject}",
		Summary:     "Remove a user from the organization (org admin only)",
		Security:    httpserver.SecurityRequirement(),
	}, h.removeOrgMember)

	huma.Register(api, huma.Operation{
		OperationID: "listMembers",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/teams/{team}/members",
		Summary:     "List members of a team",
		Security:    httpserver.SecurityRequirement(),
	}, h.listMembers)

	huma.Register(api, huma.Operation{
		OperationID: "addMember",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/teams/{team}/members",
		Summary:     "Add a user to a team (platform-engineer/admin only)",
		Security:    httpserver.SecurityRequirement(),
	}, h.addMember)

	huma.Register(api, huma.Operation{
		OperationID: "removeMember",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/teams/{team}/members/{subject}",
		Summary:     "Remove a user from a team (platform-engineer/admin only)",
		Security:    httpserver.SecurityRequirement(),
	}, h.removeMember)

	h.registerIdentityRoutes(api)
	h.registerBrokerRoutes(api)
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
	// Platform-level fine PEP: only org_creator on platform:inari may create
	// tenants (M1.W2). Tuples are synced from the Keycloak platform-admins
	// group by the PlatformGroupSync reconciler.
	ok, err := h.authz.Check(ctx, authz.UserObject(id.Subject), authz.RelationOrgCreator, authz.ObjectPlatform)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, huma.Error403Forbidden("organization creation requires the platform org_creator permission")
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

type teamPathInput struct {
	Org  string `path:"org" doc:"Tenant slug"`
	Team string `path:"team" doc:"Team name"`
}

type listMembersOutput struct {
	Body struct {
		Members []MemberView `json:"members"`
	}
}

func (h *Handler) listMembers(ctx context.Context, in *teamPathInput) (*listMembersOutput, error) {
	org, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	team, err := h.svc.store.GetTeamByName(ctx, h.svc.db.Pool, org.ID, in.Team)
	if errors.Is(err, ErrTeamNotFound) {
		return nil, huma.Error404NotFound("team not found")
	}
	if err != nil {
		return nil, err
	}
	members, err := h.svc.ListMembers(ctx, org.ID, team.ID)
	if err != nil {
		return nil, err
	}
	out := &listMembersOutput{}
	out.Body.Members = members
	return out, nil
}

type addMemberInput struct {
	Org  string `path:"org"`
	Team string `path:"team"`
	Body struct {
		Subject string `json:"subject" minLength:"1" doc:"Keycloak user id"`
	}
}

func (h *Handler) addMember(ctx context.Context, in *addMemberInput) (*struct{}, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer); err != nil {
		return nil, err
	}
	id := identity(ctx)
	err := h.svc.AddMember(ctx, id.Subject, in.Org, in.Team, in.Body.Subject)
	switch {
	case errors.Is(err, ErrUserNotFound):
		return nil, huma.Error404NotFound("user not found")
	case errors.Is(err, ErrTeamNotFound):
		return nil, huma.Error404NotFound("team not found")
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	return nil, nil
}

type removeMemberInput struct {
	Org     string `path:"org"`
	Team    string `path:"team"`
	Subject string `path:"subject"`
}

func (h *Handler) removeMember(ctx context.Context, in *removeMemberInput) (*struct{}, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer); err != nil {
		return nil, err
	}
	id := identity(ctx)
	err := h.svc.RemoveMember(ctx, id.Subject, in.Org, in.Team, in.Subject)
	switch {
	case errors.Is(err, ErrTeamNotFound):
		return nil, huma.Error404NotFound("team not found")
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	return nil, nil
}

type updateTenantInput struct {
	Org  string `path:"org" doc:"Tenant slug"`
	Body struct {
		DisplayName string `json:"displayName" minLength:"1" maxLength:"200"`
	}
}

func (h *Handler) updateTenant(ctx context.Context, in *updateTenantInput) (*tenantOutput, error) {
	org, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin)
	if err != nil {
		return nil, err
	}
	id := identity(ctx)
	updated, err := h.svc.UpdateTenantProfile(ctx, id.Subject, in.Org, in.Body.DisplayName)
	if err != nil {
		return nil, err
	}
	out := &tenantOutput{}
	out.Body.Organization = *updated
	teams, err := h.svc.ListTeams(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out.Body.Teams = teams
	return out, nil
}

type createTeamInput struct {
	Org  string `path:"org" doc:"Tenant slug"`
	Body struct {
		Name string     `json:"name" minLength:"1" maxLength:"63" pattern:"^[a-z0-9][a-z0-9-]*$" doc:"URL-safe team name"`
		Role types.Role `json:"role,omitempty" doc:"Org role the team grants (default viewer)"`
	}
}

type teamOutput struct {
	Body struct {
		Team types.Team `json:"team"`
	}
}

func (h *Handler) createTeam(ctx context.Context, in *createTeamInput) (*teamOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	role := in.Body.Role
	if role == "" {
		role = types.RoleViewer
	}
	if !role.Valid() {
		return nil, huma.Error400BadRequest("invalid role")
	}
	id := identity(ctx)
	team, err := h.svc.CreateTeam(ctx, id.Subject, in.Org, in.Body.Name, role)
	switch {
	case errors.Is(err, ErrTeamNameTaken):
		return nil, huma.Error409Conflict("team name already exists in tenant")
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	out := &teamOutput{}
	out.Body.Team = *team
	return out, nil
}

func (h *Handler) deleteTeam(ctx context.Context, in *teamPathInput) (*struct{}, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	id := identity(ctx)
	err := h.svc.DeleteTeam(ctx, id.Subject, in.Org, in.Team)
	switch {
	case errors.Is(err, ErrDefaultTeam):
		return nil, huma.Error409Conflict("default teams cannot be deleted")
	case errors.Is(err, ErrTeamNotFound):
		return nil, huma.Error404NotFound("team not found")
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	return nil, nil
}

type listOrgMembersOutput struct {
	Body struct {
		Members []OrgMemberView `json:"members"`
	}
}

func (h *Handler) listOrgMembers(ctx context.Context, in *orgPathInput) (*listOrgMembersOutput, error) {
	org, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	members, err := h.svc.ListOrgMembers(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listOrgMembersOutput{}
	out.Body.Members = members
	return out, nil
}

type putMemberInput struct {
	Org     string `path:"org"`
	Subject string `path:"subject"`
	Body    struct {
		Role types.Role `json:"role" doc:"Org role to grant"`
	}
}

func (h *Handler) putMember(ctx context.Context, in *putMemberInput) (*struct{}, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	if !in.Body.Role.Valid() {
		return nil, huma.Error400BadRequest("invalid role")
	}
	id := identity(ctx)
	err := h.svc.SetMemberRole(ctx, id.Subject, in.Org, in.Subject, in.Body.Role)
	switch {
	case errors.Is(err, ErrUserNotFound):
		return nil, huma.Error404NotFound("user not found")
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	return nil, nil
}

type removeOrgMemberInput struct {
	Org     string `path:"org"`
	Subject string `path:"subject"`
}

func (h *Handler) removeOrgMember(ctx context.Context, in *removeOrgMemberInput) (*struct{}, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	id := identity(ctx)
	err := h.svc.RemoveOrgMember(ctx, id.Subject, in.Org, in.Subject)
	switch {
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	return nil, nil
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
