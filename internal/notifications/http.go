// HTTP handlers for the notifications module (plan §5.2).
package notifications

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

// Handler exposes the notification-endpoints REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the notifications API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "createNotificationEndpoint",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/notification-endpoints",
		Summary:     "Create a notification endpoint (slack|webhook)",
		Security:    httpserver.SecurityRequirement(),
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "listNotificationEndpoints",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/notification-endpoints",
		Summary:     "List notification endpoints",
		Security:    httpserver.SecurityRequirement(),
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID: "getNotificationEndpoint",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/notification-endpoints/{id}",
		Summary:     "Get a notification endpoint",
		Security:    httpserver.SecurityRequirement(),
	}, h.get)

	huma.Register(api, huma.Operation{
		OperationID: "updateNotificationEndpoint",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/notification-endpoints/{id}",
		Summary:     "Update a notification endpoint",
		Security:    httpserver.SecurityRequirement(),
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID: "deleteNotificationEndpoint",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/notification-endpoints/{id}",
		Summary:     "Delete a notification endpoint",
		Security:    httpserver.SecurityRequirement(),
	}, h.delete)

	huma.Register(api, huma.Operation{
		OperationID: "testNotificationEndpoint",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/notification-endpoints/{id}/test",
		Summary:     "Send a test notification to an endpoint",
		Security:    httpserver.SecurityRequirement(),
	}, h.test)
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

func validationError(err error) error {
	switch {
	case errors.Is(err, ErrEndpointNotFound):
		return huma.Error404NotFound("notification endpoint not found")
	case errors.Is(err, ErrInvalidKind), errors.Is(err, ErrInvalidURL),
		errors.Is(err, ErrInvalidEvent), errors.Is(err, ErrNameRequired):
		return huma.Error422UnprocessableEntity(err.Error())
	}
	return err
}

type createInput struct {
	Org  string `path:"org"`
	Body struct {
		Name    string   `json:"name"`
		Kind    string   `json:"kind" doc:"slack | webhook"`
		URL     string   `json:"url"`
		Secret  string   `json:"secret,omitempty"`
		Events  []string `json:"events,omitempty" doc:"Empty = all events"`
		Enabled *bool    `json:"enabled,omitempty"`
	}
}

type endpointOutput struct {
	Body struct {
		Endpoint types.NotificationEndpoint `json:"endpoint"`
	}
}

func (h *Handler) create(ctx context.Context, in *createInput) (*endpointOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin)
	if err != nil {
		return nil, err
	}
	ep, err := h.svc.CreateEndpoint(ctx, id.Subject, org.ID, EndpointInput{
		Name: in.Body.Name, Kind: in.Body.Kind, URL: in.Body.URL,
		Secret: in.Body.Secret, Events: in.Body.Events, Enabled: in.Body.Enabled,
	})
	if err != nil {
		return nil, validationError(err)
	}
	out := &endpointOutput{}
	out.Body.Endpoint = *ep
	return out, nil
}

type listInput struct {
	Org string `path:"org"`
}

type listOutput struct {
	Body struct {
		Endpoints []types.NotificationEndpoint `json:"endpoints"`
	}
}

func (h *Handler) list(ctx context.Context, in *listInput) (*listOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	eps, err := h.svc.ListEndpoints(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listOutput{}
	out.Body.Endpoints = eps
	return out, nil
}

type getInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) get(ctx context.Context, in *getInput) (*endpointOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	ep, err := h.svc.GetEndpoint(ctx, org.ID, in.ID)
	if err != nil {
		return nil, validationError(err)
	}
	out := &endpointOutput{}
	out.Body.Endpoint = *ep
	return out, nil
}

type updateInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		Name    string   `json:"name,omitempty"`
		URL     string   `json:"url,omitempty"`
		Secret  string   `json:"secret,omitempty"`
		Events  []string `json:"events,omitempty"`
		Enabled *bool    `json:"enabled,omitempty"`
	}
}

func (h *Handler) update(ctx context.Context, in *updateInput) (*endpointOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin)
	if err != nil {
		return nil, err
	}
	ep, err := h.svc.UpdateEndpoint(ctx, id.Subject, org.ID, in.ID, EndpointInput{
		Name: in.Body.Name, URL: in.Body.URL, Secret: in.Body.Secret,
		Events: in.Body.Events, Enabled: in.Body.Enabled,
	})
	if err != nil {
		return nil, validationError(err)
	}
	out := &endpointOutput{}
	out.Body.Endpoint = *ep
	return out, nil
}

type deleteInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

type deleteOutput struct {
	Status int
}

func (h *Handler) delete(ctx context.Context, in *deleteInput) (*deleteOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin)
	if err != nil {
		return nil, err
	}
	if err := h.svc.DeleteEndpoint(ctx, id.Subject, org.ID, in.ID); err != nil {
		return nil, validationError(err)
	}
	return &deleteOutput{Status: http.StatusNoContent}, nil
}

type testInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

type testOutput struct {
	Body struct {
		Delivery types.NotificationDelivery `json:"delivery"`
	}
}

func (h *Handler) test(ctx context.Context, in *testInput) (*testOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin)
	if err != nil {
		return nil, err
	}
	d, err := h.svc.TestEndpoint(ctx, id.Subject, org.ID, in.ID)
	if err != nil {
		return nil, validationError(err)
	}
	out := &testOutput{}
	out.Body.Delivery = *d
	return out, nil
}
