// HTTP handlers for the identity section (OIDC clients/scopes) and the
// declarative RBAC mappings route (Settings design §3.1). All routes are
// org-admin gated; client secrets are returned exactly once at create/rotate
// and never persisted server-side.
package tenancy

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/config"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/types"
)

// WithScopesCatalog wires the read-only per-service audiences/scopes catalog
// served at GET /tenants/{org}/identity/scopes.
func (h *Handler) WithScopesCatalog(catalog []config.ServiceScopes) *Handler {
	h.scopes = catalog
	return h
}

// registerIdentityRoutes mounts the identity + RBAC mappings surface; called
// from RegisterRoutes so the OpenAPI export stays in sync.
func (h *Handler) registerIdentityRoutes(api huma.API) {
	sec := httpserver.SecurityRequirement()

	huma.Register(api, huma.Operation{
		OperationID: "listIdentityClients",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/identity/clients",
		Summary:     "List OIDC clients of a tenant (org admin only)",
		Security:    sec,
	}, h.listIdentityClients)

	huma.Register(api, huma.Operation{
		OperationID: "createIdentityClient",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/identity/clients",
		Summary:     "Create an OIDC client; the secret is returned exactly once (org admin only)",
		Security:    sec,
	}, h.createIdentityClient)

	huma.Register(api, huma.Operation{
		OperationID: "getIdentityClient",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/identity/clients/{clientId}",
		Summary:     "Get an OIDC client (org admin only)",
		Security:    sec,
	}, h.getIdentityClient)

	huma.Register(api, huma.Operation{
		OperationID: "updateIdentityClient",
		Method:      http.MethodPatch,
		Path:        "/api/v1/tenants/{org}/identity/clients/{clientId}",
		Summary:     "Update an OIDC client (org admin only)",
		Security:    sec,
	}, h.updateIdentityClient)

	huma.Register(api, huma.Operation{
		OperationID: "disableIdentityClient",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/identity/clients/{clientId}",
		Summary:     "Disable an OIDC client (org admin only; row retained for audit)",
		Security:    sec,
	}, h.disableIdentityClient)

	huma.Register(api, huma.Operation{
		OperationID: "putIdentityClientScopes",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/identity/clients/{clientId}/scopes",
		Summary:     "Replace the scopes of an OIDC client (org admin only)",
		Security:    sec,
	}, h.putIdentityClientScopes)

	huma.Register(api, huma.Operation{
		OperationID: "rotateIdentityClientSecret",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/identity/clients/{clientId}/secret:rotate",
		Summary:     "Rotate the client secret; the new value is returned exactly once (org admin only)",
		Security:    sec,
	}, h.rotateIdentityClientSecret)

	huma.Register(api, huma.Operation{
		OperationID: "listIdentityScopes",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/identity/scopes",
		Summary:     "Read-only catalog of per-service audiences/scopes (org admin only)",
		Security:    sec,
	}, h.listIdentityScopes)

	huma.Register(api, huma.Operation{
		OperationID: "putRBACMappings",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/rbac/mappings",
		Summary:     "Declarative bulk set of team→role mappings, applied atomically (org admin only)",
		Security:    sec,
	}, h.putRBACMappings)
}

type listIdentityClientsOutput struct {
	Body struct {
		Clients []types.IdentityClient `json:"clients"`
	}
}

func (h *Handler) listIdentityClients(ctx context.Context, in *orgPathInput) (*listIdentityClientsOutput, error) {
	org, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin)
	if err != nil {
		return nil, err
	}
	clients, err := h.svc.ListIdentityClients(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listIdentityClientsOutput{}
	out.Body.Clients = clients
	return out, nil
}

type createIdentityClientInput struct {
	Org  string `path:"org"`
	Body struct {
		Name         string   `json:"name" minLength:"1" maxLength:"63" pattern:"^[a-z0-9][a-z0-9-]*$" doc:"URL-safe client name (clientId becomes org-<org>-<name>)"`
		Type         string   `json:"type" enum:"service,public" doc:"service = confidential client-credentials; public = browser/native with redirect URIs"`
		Audiences    []string `json:"audiences,omitempty"`
		Scopes       []string `json:"scopes,omitempty"`
		RedirectURIs []string `json:"redirectUris,omitempty"`
	}
}

type identityClientOutput struct {
	Body struct {
		Client types.IdentityClient `json:"client"`
	}
}

type createIdentityClientOutput struct {
	Body struct {
		Client types.IdentityClient `json:"client"`
		Secret string               `json:"secret,omitempty" doc:"Returned exactly once; never stored server-side"`
	}
}

func (h *Handler) createIdentityClient(ctx context.Context, in *createIdentityClientInput) (*createIdentityClientOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	id := identity(ctx)
	client, secret, err := h.svc.CreateIdentityClient(ctx, id.Subject, in.Org, &types.IdentityClient{
		Name:         in.Body.Name,
		Type:         in.Body.Type,
		Audiences:    in.Body.Audiences,
		Scopes:       in.Body.Scopes,
		RedirectURIs: in.Body.RedirectURIs,
	})
	switch {
	case errors.Is(err, ErrClientNameTaken):
		return nil, huma.Error409Conflict("client name already exists in tenant")
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	out := &createIdentityClientOutput{}
	out.Body.Client = *client
	out.Body.Secret = secret
	return out, nil
}

type identityClientPathInput struct {
	Org      string `path:"org"`
	ClientID string `path:"clientId"`
}

func (h *Handler) getIdentityClient(ctx context.Context, in *identityClientPathInput) (*identityClientOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	client, err := h.svc.GetIdentityClient(ctx, in.Org, in.ClientID)
	return identityClientResult(client, err)
}

type updateIdentityClientInput struct {
	Org      string `path:"org"`
	ClientID string `path:"clientId"`
	Body     struct {
		Name         *string   `json:"name,omitempty" minLength:"1" maxLength:"63"`
		Audiences    *[]string `json:"audiences,omitempty"`
		Scopes       *[]string `json:"scopes,omitempty"`
		RedirectURIs *[]string `json:"redirectUris,omitempty"`
	}
}

func (h *Handler) updateIdentityClient(ctx context.Context, in *updateIdentityClientInput) (*identityClientOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	client, err := h.svc.GetIdentityClient(ctx, in.Org, in.ClientID)
	if errors.Is(err, ErrClientNotFound) {
		return nil, huma.Error404NotFound("identity client not found")
	}
	if errors.Is(err, ErrOrgNotFound) {
		return nil, huma.Error404NotFound("organization not found")
	}
	if err != nil {
		return nil, err
	}
	if in.Body.Name != nil {
		client.Name = *in.Body.Name
	}
	if in.Body.Audiences != nil {
		client.Audiences = *in.Body.Audiences
	}
	if in.Body.Scopes != nil {
		client.Scopes = *in.Body.Scopes
	}
	if in.Body.RedirectURIs != nil {
		client.RedirectURIs = *in.Body.RedirectURIs
	}
	id := identity(ctx)
	if err := h.svc.UpdateIdentityClient(ctx, id.Subject, in.Org, client); err != nil {
		return nil, err
	}
	return identityClientResult(client, nil)
}

func (h *Handler) disableIdentityClient(ctx context.Context, in *identityClientPathInput) (*struct{}, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	id := identity(ctx)
	err := h.svc.DisableIdentityClient(ctx, id.Subject, in.Org, in.ClientID)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return nil, huma.Error404NotFound("identity client not found")
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	return nil, nil
}

type putClientScopesInput struct {
	Org      string `path:"org"`
	ClientID string `path:"clientId"`
	Body     struct {
		Scopes []string `json:"scopes"`
	}
}

func (h *Handler) putIdentityClientScopes(ctx context.Context, in *putClientScopesInput) (*identityClientOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	client, err := h.svc.GetIdentityClient(ctx, in.Org, in.ClientID)
	if errors.Is(err, ErrClientNotFound) {
		return nil, huma.Error404NotFound("identity client not found")
	}
	if errors.Is(err, ErrOrgNotFound) {
		return nil, huma.Error404NotFound("organization not found")
	}
	if err != nil {
		return nil, err
	}
	client.Scopes = in.Body.Scopes
	id := identity(ctx)
	if err := h.svc.UpdateIdentityClient(ctx, id.Subject, in.Org, client); err != nil {
		return nil, err
	}
	return identityClientResult(client, nil)
}

type rotateSecretOutput struct {
	Body struct {
		Secret string `json:"secret" doc:"Returned exactly once; never stored server-side"`
	}
}

func (h *Handler) rotateIdentityClientSecret(ctx context.Context, in *identityClientPathInput) (*rotateSecretOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	id := identity(ctx)
	secret, err := h.svc.RotateIdentityClientSecret(ctx, id.Subject, in.Org, in.ClientID)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return nil, huma.Error404NotFound("identity client not found")
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	out := &rotateSecretOutput{}
	out.Body.Secret = secret
	return out, nil
}

type listIdentityScopesOutput struct {
	Body struct {
		Scopes []config.ServiceScopes `json:"scopes"`
	}
}

func (h *Handler) listIdentityScopes(ctx context.Context, in *orgPathInput) (*listIdentityScopesOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	out := &listIdentityScopesOutput{}
	out.Body.Scopes = h.scopes
	return out, nil
}

type putRBACMappingsInput struct {
	Org  string `path:"org"`
	Body struct {
		Mappings []types.TeamRoleMapping `json:"mappings" doc:"Declarative team→role set; applied atomically"`
	}
}

type putRBACMappingsOutput struct {
	Body struct {
		Changes []types.TeamRoleChange `json:"changes"`
	}
}

func (h *Handler) putRBACMappings(ctx context.Context, in *putRBACMappingsInput) (*putRBACMappingsOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	for _, m := range in.Body.Mappings {
		if !m.Role.Valid() {
			return nil, huma.Error400BadRequest("invalid role: " + string(m.Role))
		}
	}
	id := identity(ctx)
	changes, err := h.svc.SetRBACMappings(ctx, id.Subject, in.Org, in.Body.Mappings)
	switch {
	case errors.Is(err, ErrTeamNotFound):
		return nil, huma.Error404NotFound("team not found")
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	out := &putRBACMappingsOutput{}
	out.Body.Changes = changes
	return out, nil
}

func identityClientResult(client *types.IdentityClient, err error) (*identityClientOutput, error) {
	switch {
	case errors.Is(err, ErrClientNotFound):
		return nil, huma.Error404NotFound("identity client not found")
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	out := &identityClientOutput{}
	out.Body.Client = *client
	return out, nil
}
