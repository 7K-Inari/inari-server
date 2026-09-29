// HTTP handlers for platform-level administration (platform admins API).
package tenancy

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
)

// PlatformHandler exposes the platform admins API (RBAC redesign Phase A):
// membership management for the Keycloak platform admin group. All routes
// are gated by the OpenFGA org_creator check on platform:inari — the same
// permission PlatformGroupSync derives from this group, so only existing
// platform admins can manage the group.
type PlatformHandler struct {
	svc   *Service
	authz authz.Authorizer
	group string
}

// NewPlatformHandler builds the handler; group is the Keycloak platform
// admin group (config INARI_PLATFORM_ADMIN_GROUP).
func NewPlatformHandler(svc *Service, az authz.Authorizer, group string) *PlatformHandler {
	return &PlatformHandler{svc: svc, authz: az, group: group}
}

// RegisterRoutes mounts the platform admins API on the huma API instance.
func (h *PlatformHandler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "listPlatformAdmins",
		Method:      http.MethodGet,
		Path:        "/api/v1/platform/admins",
		Summary:     "List platform admins (members of the Keycloak platform admin group)",
		Security:    httpserver.SecurityRequirement(),
	}, h.listAdmins)

	huma.Register(api, huma.Operation{
		OperationID: "grantPlatformAdmin",
		Method:      http.MethodPut,
		Path:        "/api/v1/platform/admins/{subject}",
		Summary:     "Grant platform admin (joins the platform admin group; org_creator tuple converges via PlatformGroupSync)",
		Security:    httpserver.SecurityRequirement(),
	}, h.grantAdmin)

	huma.Register(api, huma.Operation{
		OperationID: "revokePlatformAdmin",
		Method:      http.MethodDelete,
		Path:        "/api/v1/platform/admins/{subject}",
		Summary:     "Revoke platform admin (leaves the platform admin group; idempotent)",
		Security:    httpserver.SecurityRequirement(),
	}, h.revokeAdmin)
}

// authorizeOrgCreator gates every platform admins route on the org_creator
// relation on platform:inari (same PEP as tenant creation).
func (h *PlatformHandler) authorizeOrgCreator(ctx context.Context) (string, error) {
	id := identity(ctx)
	if id == nil {
		return "", huma.Error401Unauthorized("unauthenticated")
	}
	ok, err := h.authz.Check(ctx, authz.UserObject(id.Subject), authz.RelationOrgCreator, authz.ObjectPlatform)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", huma.Error403Forbidden("platform admin management requires the platform org_creator permission")
	}
	return id.Subject, nil
}

type listPlatformAdminsOutput struct {
	Body struct {
		Admins []PlatformAdminView `json:"admins"`
	}
}

func (h *PlatformHandler) listAdmins(ctx context.Context, _ *struct{}) (*listPlatformAdminsOutput, error) {
	if _, err := h.authorizeOrgCreator(ctx); err != nil {
		return nil, err
	}
	admins, err := h.svc.ListPlatformAdmins(ctx, h.group)
	if err != nil {
		return nil, err
	}
	out := &listPlatformAdminsOutput{}
	out.Body.Admins = admins
	return out, nil
}

type platformAdminSubjectInput struct {
	Subject string `path:"subject" doc:"Keycloak user id or email of the user to grant/revoke"`
}

func (h *PlatformHandler) grantAdmin(ctx context.Context, in *platformAdminSubjectInput) (*struct{}, error) {
	actor, err := h.authorizeOrgCreator(ctx)
	if err != nil {
		return nil, err
	}
	err = h.svc.GrantPlatformAdmin(ctx, actor, h.group, in.Subject)
	if errors.Is(err, ErrUserNotFound) {
		return nil, huma.Error404NotFound("user not found")
	}
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (h *PlatformHandler) revokeAdmin(ctx context.Context, in *platformAdminSubjectInput) (*struct{}, error) {
	actor, err := h.authorizeOrgCreator(ctx)
	if err != nil {
		return nil, err
	}
	err = h.svc.RevokePlatformAdmin(ctx, actor, h.group, in.Subject)
	if errors.Is(err, ErrUserNotFound) {
		return nil, huma.Error404NotFound("user not found")
	}
	if err != nil {
		return nil, err
	}
	return nil, nil
}
