// Role engine REST surface (ADR-0013): org role CRUD + the static
// permission catalog. Guardrail violations (built-in delete/rename,
// delete-in-use, tenant.admin lockout) answer 409 with an explanation.
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

// registerRoleRoutes mounts the roles API; called from RegisterRoutes so
// the OpenAPI export stays in sync.
func (h *Handler) registerRoleRoutes(api huma.API) {
	sec := httpserver.SecurityRequirement()

	huma.Register(api, huma.Operation{
		OperationID: "listRoles",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/roles",
		Summary:     "List org roles (built-in and custom)",
		Security:    sec,
	}, h.listRoles)

	huma.Register(api, huma.Operation{
		OperationID: "createRole",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/roles",
		Summary:     "Create a custom org role (tenant.rbac.manage)",
		Security:    sec,
	}, h.createRole)

	huma.Register(api, huma.Operation{
		OperationID: "getRole",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/roles/{role}",
		Summary:     "Get one org role by name or ID",
		Security:    sec,
	}, h.getRole)

	huma.Register(api, huma.Operation{
		OperationID: "updateRole",
		Method:      http.MethodPatch,
		Path:        "/api/v1/tenants/{org}/roles/{role}",
		Summary:     "Edit a role (tenant.rbac.manage; built-in names are immutable; the tenant.admin guardrail applies)",
		Security:    sec,
	}, h.updateRole)

	huma.Register(api, huma.Operation{
		OperationID: "deleteRole",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/roles/{role}",
		Summary:     "Delete a custom role (tenant.rbac.manage; built-ins are never deletable)",
		Security:    sec,
	}, h.deleteRole)

	huma.Register(api, huma.Operation{
		OperationID: "getPermissionCatalog",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/permissions/catalog",
		Summary:     "Static permission catalog for the role editor",
		Security:    sec,
	}, h.getPermissionCatalog)
}

type listRolesOutput struct {
	Body struct {
		Roles []types.Role `json:"roles"`
	}
}

func (h *Handler) listRoles(ctx context.Context, in *orgPathInput) (*listRolesOutput, error) {
	org, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	roles, err := h.svc.ListRoles(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listRolesOutput{}
	out.Body.Roles = roles
	return out, nil
}

type createRoleInput struct {
	Org  string `path:"org"`
	Body struct {
		Name        string   `json:"name" minLength:"1" maxLength:"63" pattern:"^[a-z0-9][a-z0-9-]*$" doc:"DNS-1123 role name (ClusterRole suffix tenant-<slug>-<name>)"`
		DisplayName string   `json:"displayName,omitempty" maxLength:"200"`
		Description string   `json:"description,omitempty" maxLength:"500"`
		Permissions []string `json:"permissions" doc:"Permission-catalog slugs (GET permissions/catalog)"`
	}
}

type roleOutput struct {
	Body struct {
		Role types.Role `json:"role"`
	}
}

func (h *Handler) createRole(ctx context.Context, in *createRoleInput) (*roleOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRBACManage); err != nil {
		return nil, err
	}
	id := identity(ctx)
	role, err := h.svc.CreateRole(ctx, id.Subject, in.Org, &types.Role{
		Name:        in.Body.Name,
		DisplayName: in.Body.DisplayName,
		Description: in.Body.Description,
		Permissions: in.Body.Permissions,
	})
	if err != nil {
		return nil, roleError(err)
	}
	out := &roleOutput{}
	out.Body.Role = *role
	return out, nil
}

type rolePathInput struct {
	Org  string `path:"org"`
	Role string `path:"role" doc:"Role name or ID"`
}

func (h *Handler) getRole(ctx context.Context, in *rolePathInput) (*roleOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead); err != nil {
		return nil, err
	}
	role, err := h.svc.GetRole(ctx, in.Org, in.Role)
	if err != nil {
		return nil, roleError(err)
	}
	out := &roleOutput{}
	out.Body.Role = *role
	return out, nil
}

type updateRoleInput struct {
	Org  string `path:"org"`
	Role string `path:"role"`
	Body RolePatch
}

func (h *Handler) updateRole(ctx context.Context, in *updateRoleInput) (*roleOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRBACManage); err != nil {
		return nil, err
	}
	id := identity(ctx)
	role, err := h.svc.UpdateRole(ctx, id.Subject, in.Org, in.Role, in.Body)
	if err != nil {
		return nil, roleError(err)
	}
	out := &roleOutput{}
	out.Body.Role = *role
	return out, nil
}

func (h *Handler) deleteRole(ctx context.Context, in *rolePathInput) (*struct{}, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRBACManage); err != nil {
		return nil, err
	}
	id := identity(ctx)
	if err := h.svc.DeleteRole(ctx, id.Subject, in.Org, in.Role); err != nil {
		return nil, roleError(err)
	}
	return nil, nil
}

type permissionCatalogOutput struct {
	Body struct {
		Permissions []authz.Permission `json:"permissions"`
	}
}

func (h *Handler) getPermissionCatalog(ctx context.Context, in *orgPathInput) (*permissionCatalogOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead); err != nil {
		return nil, err
	}
	out := &permissionCatalogOutput{}
	out.Body.Permissions = h.svc.PermissionCatalog()
	return out, nil
}

// roleError maps role-service errors onto HTTP status codes; validation
// errors (bad name/permission) are 400, guardrail violations 409.
func roleError(err error) error {
	var inputErr *RoleInputError
	switch {
	case errors.As(err, &inputErr):
		return huma.Error400BadRequest(inputErr.Error())
	case errors.Is(err, ErrRoleNotFound):
		return huma.Error404NotFound("role not found")
	case errors.Is(err, ErrOrgNotFound):
		return huma.Error404NotFound("organization not found")
	case errors.Is(err, ErrRoleNameTaken):
		return huma.Error409Conflict("role name already exists in tenant")
	case errors.Is(err, ErrBuiltinRole):
		return huma.Error409Conflict("built-in roles cannot be deleted or renamed")
	case errors.Is(err, ErrRoleInUse):
		return huma.Error409Conflict("role is still bound to teams; remap them first")
	case errors.Is(err, ErrAdminGuardrail):
		return huma.Error409Conflict("at least one team must retain the tenant.admin permission")
	case err != nil:
		return err
	}
	return nil
}
