// HTTP handlers for the user git connections module (W4). Connections are
// self-service: any org member (viewer relation) manages their OWN
// connections; the user identity is always derived from the JWT subject,
// never from request input. Tokens never appear in responses.
package usergit

import (
	"context"
	"errors"
	"net/http"
	"net/url"

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

// Handler exposes the user git connections REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the user git connections API on the huma API.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "listGitConnections",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/git-connections",
		Summary:     "List the caller's own git connections (metadata only)",
		Security:    httpserver.SecurityRequirement(),
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID: "authorizeGitConnection",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/git-connections/{provider}/authorize",
		Summary:     "Start the git OAuth flow (302 to the provider consent URL)",
		Security:    httpserver.SecurityRequirement(),
	}, h.authorize)

	huma.Register(api, huma.Operation{
		OperationID: "gitConnectionCallback",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/git-connections/{provider}/callback",
		Summary:     "OAuth callback (302 back to the UI)",
		Security:    httpserver.SecurityRequirement(),
	}, h.callback)

	huma.Register(api, huma.Operation{
		OperationID: "disconnectGitConnection",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/git-connections/{provider}",
		Summary:     "Revoke the provider grant and delete the connection",
		Security:    httpserver.SecurityRequirement(),
	}, h.disconnect)
}

// authorizeOrg performs coarse PEP (org claim) + fine PEP (OpenFGA Check).
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

type orgPathInput struct {
	Org string `path:"org" doc:"Tenant slug"`
}

type listConnectionsOutput struct {
	Body struct {
		Connections []Connection `json:"connections"`
	}
}

func (h *Handler) list(ctx context.Context, in *orgPathInput) (*listConnectionsOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	conns, err := h.svc.List(ctx, org.ID, id.Subject)
	if err != nil {
		return nil, err
	}
	out := &listConnectionsOutput{}
	out.Body.Connections = conns
	return out, nil
}

type authorizeInput struct {
	Org      string `path:"org"`
	Provider string `path:"provider"`
	Body     struct {
		APIBase string `json:"apiBase,omitempty" doc:"GHE/self-hosted API base (must be allowlisted); empty = github.com"`
	}
}

type redirectOutput struct {
	Status   int
	Location string `header:"Location"`
}

func (h *Handler) authorize(ctx context.Context, in *authorizeInput) (*redirectOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	url, err := h.svc.BeginAuthorize(ctx, org.ID, id.Subject, in.Provider, in.Body.APIBase)
	if errors.Is(err, ErrUnknownProvider) {
		return nil, huma.Error404NotFound("unknown git provider")
	}
	if errors.Is(err, ErrProviderNotEnabled) {
		return nil, huma.Error501NotImplemented("git provider not enabled")
	}
	if errors.Is(err, ErrInvalidInput) {
		return nil, huma.Error422UnprocessableEntity(err.Error())
	}
	if err != nil {
		return nil, err
	}
	return &redirectOutput{Status: http.StatusFound, Location: url}, nil
}

type callbackInput struct {
	Org      string `path:"org"`
	Provider string `path:"provider"`
	Code     string `query:"code"`
	State    string `query:"state"`
}

// callback always redirects back to the UI (302): success carries
// ?connected=<provider>, failure a safe ?error=<code> — internal details
// are never reflected to the browser.
func (h *Handler) callback(ctx context.Context, in *callbackInput) (*redirectOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	_ = org
	if _, err := h.svc.CompleteAuthorize(ctx, id.Subject, in.State, in.Code); err != nil {
		return &redirectOutput{Status: http.StatusFound, Location: h.uiErrorURL(in.Provider, callbackErrorCode(err))}, nil
	}
	return &redirectOutput{Status: http.StatusFound, Location: h.uiSuccessURL(in.Provider)}, nil
}

func callbackErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrStateInvalid):
		return "state_invalid"
	case errors.Is(err, ErrUnknownProvider):
		return "unknown_provider"
	case errors.Is(err, ErrProviderNotEnabled):
		return "provider_not_enabled"
	default:
		return "exchange_failed"
	}
}

func (h *Handler) uiSuccessURL(provider string) string {
	sep := "?"
	if u, err := url.Parse(h.svc.UIReturnURL()); err == nil && u.RawQuery != "" {
		sep = "&"
	}
	return h.svc.UIReturnURL() + sep + "connected=" + url.QueryEscape(provider)
}

func (h *Handler) uiErrorURL(provider, code string) string {
	sep := "?"
	if u, err := url.Parse(h.svc.UIReturnURL()); err == nil && u.RawQuery != "" {
		sep = "&"
	}
	return h.svc.UIReturnURL() + sep + "provider=" + url.QueryEscape(provider) + "&error=" + url.QueryEscape(code)
}

type disconnectInput struct {
	Org      string `path:"org"`
	Provider string `path:"provider"`
}

type disconnectOutput struct {
	Status int
}

func (h *Handler) disconnect(ctx context.Context, in *disconnectInput) (*disconnectOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	err = h.svc.Disconnect(ctx, id.Subject, org.ID, id.Subject, in.Provider)
	if errors.Is(err, ErrNotFound) {
		return nil, huma.Error404NotFound("git connection not found")
	}
	if errors.Is(err, ErrUnknownProvider) {
		return nil, huma.Error404NotFound("unknown git provider")
	}
	if errors.Is(err, ErrProviderNotEnabled) {
		return nil, huma.Error501NotImplemented("git provider not enabled")
	}
	if err != nil {
		return nil, err
	}
	return &disconnectOutput{Status: http.StatusNoContent}, nil
}
