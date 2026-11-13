package resourcetargets

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type TenantResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "listResourceTargetProviders", Method: http.MethodGet,
		Path: "/api/v1/tenants/{org}/resource-target-providers", Summary: "List resource target provider config and UI schemas",
		Security: httpserver.SecurityRequirement()}, h.providers)
	huma.Register(api, huma.Operation{OperationID: "listResourceTargets", Method: http.MethodGet,
		Path: "/api/v1/tenants/{org}/resource-targets", Summary: "List caller-entitled shared resource targets",
		Security: httpserver.SecurityRequirement()}, h.list)
	huma.Register(api, huma.Operation{OperationID: "registerResourceTarget", Method: http.MethodPost,
		Path: "/api/v1/tenants/{org}/resource-targets", Summary: "Adopt an existing inventory resource as a shared target",
		Security: httpserver.SecurityRequirement()}, h.create)
	huma.Register(api, huma.Operation{OperationID: "getResourceTarget", Method: http.MethodGet,
		Path: "/api/v1/tenants/{org}/resource-targets/{id}", Summary: "Get a caller-visible resource target",
		Security: httpserver.SecurityRequirement()}, h.get)
	huma.Register(api, huma.Operation{OperationID: "updateResourceTarget", Method: http.MethodPatch,
		Path: "/api/v1/tenants/{org}/resource-targets/{id}", Summary: "Update target policy with optimistic concurrency",
		Security: httpserver.SecurityRequirement()}, h.update)
	huma.Register(api, huma.Operation{OperationID: "deleteResourceTarget", Method: http.MethodDelete,
		Path: "/api/v1/tenants/{org}/resource-targets/{id}", Summary: "Delete a target overlay without deleting its resource",
		Security: httpserver.SecurityRequirement()}, h.delete)
	huma.Register(api, huma.Operation{OperationID: "setResourceTargetGrant", Method: http.MethodPut,
		Path: "/api/v1/tenants/{org}/resource-targets/{id}/grants/{teamId}", Summary: "Set a team's view, use, or provision grant",
		Security: httpserver.SecurityRequirement()}, h.setGrant)
	huma.Register(api, huma.Operation{OperationID: "revokeResourceTargetGrant", Method: http.MethodDelete,
		Path: "/api/v1/tenants/{org}/resource-targets/{id}/grants/{teamId}", Summary: "Revoke a team's target grant",
		Security: httpserver.SecurityRequirement()}, h.revokeGrant)
}

func (h *Handler) authorize(ctx context.Context, slug string, manage bool) (*types.Organization, *authn.Identity, error) {
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
	if manage {
		allowed, err := h.authz.Check(ctx, authz.UserObject(id.Subject), authz.RelationResourceTargetsManage, authz.OrgObject(org.ID))
		if err != nil {
			return nil, nil, huma.Error503ServiceUnavailable("authorization backend unavailable")
		}
		if !allowed {
			return nil, nil, huma.Error403Forbidden("insufficient permissions")
		}
	}
	return org, id, nil
}

func targetHTTPError(err error) error {
	if err == nil {
		return nil
	}
	var validation *ValidationError
	var authorization *AuthorizationError
	switch {
	case errors.Is(err, ErrTargetDenied):
		return huma.Error403Forbidden("resource target grant required")
	case errors.Is(err, ErrTargetNotFound):
		return huma.Error404NotFound("resource target not found")
	case errors.Is(err, ErrStaleRevision):
		return huma.Error409Conflict("resource target changed; retry with its current revision")
	case errors.Is(err, ErrUnavailable), errors.Is(err, ErrConflict):
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, ErrInvalidInput), errors.As(err, &validation):
		return huma.Error422UnprocessableEntity(err.Error())
	case errors.As(err, &authorization):
		return huma.Error503ServiceUnavailable("authorization backend unavailable")
	default:
		return err
	}
}

type orgInput struct {
	Org string `path:"org"`
}

type providersOutput struct {
	Body struct {
		Providers []ProviderDescriptor `json:"providers"`
	}
}

func (h *Handler) providers(ctx context.Context, in *orgInput) (*providersOutput, error) {
	if _, _, err := h.authorize(ctx, in.Org, false); err != nil {
		return nil, err
	}
	out := &providersOutput{}
	out.Body.Providers = h.svc.Providers()
	return out, nil
}

type listInput struct {
	Org                string `path:"org"`
	Capability         string `query:"capability"`
	Action             string `query:"action" enum:"view,use,provision"`
	ResourceKind       string `query:"resourceKind"`
	ResourceID         string `query:"resourceId"`
	IncludeUnavailable bool   `query:"includeUnavailable"`
}

type listOutput struct {
	Body struct {
		Targets []Target `json:"targets"`
	}
}

func (h *Handler) list(ctx context.Context, in *listInput) (*listOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, false)
	if err != nil {
		return nil, err
	}
	filter := ListFilter{Capability: in.Capability, Action: Action(in.Action), IncludeUnavailable: in.IncludeUnavailable}
	if in.ResourceKind != "" || in.ResourceID != "" {
		filter.ResourceRef = &TargetResourceRef{Kind: in.ResourceKind, ID: in.ResourceID}
	}
	targets, err := h.svc.List(ctx, org.ID, id.Subject, filter)
	if err != nil {
		return nil, targetHTTPError(err)
	}
	out := &listOutput{}
	out.Body.Targets = targets
	return out, nil
}

type createInput struct {
	Org  string `path:"org"`
	Body struct {
		Name        string            `json:"name" minLength:"1" maxLength:"100"`
		ResourceRef TargetResourceRef `json:"resourceRef"`
		Capability  string            `json:"capability" minLength:"1"`
		Config      json.RawMessage   `json:"config,omitempty"`
		IsDefault   bool              `json:"isDefault,omitempty"`
	}
}

type targetOutput struct {
	Body struct {
		Target *Target `json:"target"`
	}
}

func (h *Handler) create(ctx context.Context, in *createInput) (*targetOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, true)
	if err != nil {
		return nil, err
	}
	target, err := h.svc.Create(ctx, org.ID, "user:"+id.Subject, CreateInput{
		Name: in.Body.Name, ResourceRef: in.Body.ResourceRef, Capability: in.Body.Capability,
		Config: in.Body.Config, IsDefault: in.Body.IsDefault,
	})
	if err != nil {
		return nil, targetHTTPError(err)
	}
	out := &targetOutput{}
	out.Body.Target = target
	return out, nil
}

type targetInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) get(ctx context.Context, in *targetInput) (*targetOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, false)
	if err != nil {
		return nil, err
	}
	target, err := h.svc.Get(ctx, org.ID, id.Subject, in.ID)
	if err != nil {
		return nil, targetHTTPError(err)
	}
	out := &targetOutput{}
	out.Body.Target = target
	return out, nil
}

type updateInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		Name      *string          `json:"name,omitempty"`
		Config    *json.RawMessage `json:"config,omitempty"`
		Enabled   *bool            `json:"enabled,omitempty"`
		IsDefault *bool            `json:"isDefault,omitempty"`
		Revision  int64            `json:"revision" minimum:"1"`
	}
}

func (h *Handler) update(ctx context.Context, in *updateInput) (*targetOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, true)
	if err != nil {
		return nil, err
	}
	target, err := h.svc.Update(ctx, org.ID, in.ID, "user:"+id.Subject, PatchInput{
		Name: in.Body.Name, Config: in.Body.Config, Enabled: in.Body.Enabled, IsDefault: in.Body.IsDefault, Revision: in.Body.Revision,
	})
	if err != nil {
		return nil, targetHTTPError(err)
	}
	out := &targetOutput{}
	out.Body.Target = target
	return out, nil
}

type deleteOutput struct {
	Body struct {
		Deleted bool `json:"deleted"`
	}
}

func (h *Handler) delete(ctx context.Context, in *targetInput) (*deleteOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, true)
	if err != nil {
		return nil, err
	}
	if err := h.svc.Delete(ctx, org.ID, in.ID, "user:"+id.Subject); err != nil {
		return nil, targetHTTPError(err)
	}
	out := &deleteOutput{}
	out.Body.Deleted = true
	return out, nil
}

type grantInput struct {
	Org    string `path:"org"`
	ID     string `path:"id"`
	TeamID string `path:"teamId"`
	Body   struct {
		Relation string `json:"relation" enum:"view,use,provision"`
	}
}

type grantOutput struct {
	Body struct {
		Grant *Grant `json:"grant"`
	}
}

func (h *Handler) setGrant(ctx context.Context, in *grantInput) (*grantOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, true)
	if err != nil {
		return nil, err
	}
	grant, err := h.svc.SetGrant(ctx, org.ID, in.ID, in.TeamID, Action(in.Body.Relation), "user:"+id.Subject)
	if err != nil {
		return nil, targetHTTPError(err)
	}
	out := &grantOutput{}
	out.Body.Grant = grant
	return out, nil
}

type revokeInput struct {
	Org    string `path:"org"`
	ID     string `path:"id"`
	TeamID string `path:"teamId"`
}

func (h *Handler) revokeGrant(ctx context.Context, in *revokeInput) (*deleteOutput, error) {
	org, id, err := h.authorize(ctx, in.Org, true)
	if err != nil {
		return nil, err
	}
	if err := h.svc.RevokeGrant(ctx, org.ID, in.ID, in.TeamID, "user:"+id.Subject); err != nil {
		return nil, targetHTTPError(err)
	}
	out := &deleteOutput{}
	out.Body.Deleted = true
	return out, nil
}
