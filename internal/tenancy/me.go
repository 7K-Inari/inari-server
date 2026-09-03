package tenancy

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
)

// MeHandler exposes the caller's platform-level permission surface (M1.W2),
// backed by OpenFGA checks. The response is a flat struct so new flags are
// additive, non-breaking changes.
type MeHandler struct {
	authz authz.Authorizer
}

func NewMeHandler(az authz.Authorizer) *MeHandler {
	return &MeHandler{authz: az}
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
	}
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
	return out, nil
}
