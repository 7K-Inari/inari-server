// HTTP handlers for IdP brokering (Settings design §3.3, OIDC-only v1).
// All routes are org-admin gated; the IdP client secret is accepted on
// create/update (write-only in Keycloak) and never returned. One IdP per
// org in v1.
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

// registerBrokerRoutes mounts the IdP brokering surface; called from
// RegisterRoutes so the OpenAPI export stays in sync.
func (h *Handler) registerBrokerRoutes(api huma.API) {
	sec := httpserver.SecurityRequirement()

	huma.Register(api, huma.Operation{
		OperationID: "listIdentityProviders",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/identity/providers",
		Summary:     "List brokered identity providers of a tenant (org admin only; at most one in v1)",
		Security:    sec,
	}, h.listBrokeredIdPs)

	huma.Register(api, huma.Operation{
		OperationID: "createIdentityProvider",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/identity/providers",
		Summary:     "Broker an OIDC identity provider into the tenant; the client secret is write-only (org admin only)",
		Security:    sec,
	}, h.createBrokeredIdP)

	huma.Register(api, huma.Operation{
		OperationID: "getIdentityProvider",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/identity/providers/{alias}",
		Summary:     "Get a brokered identity provider (org admin only)",
		Security:    sec,
	}, h.getBrokeredIdP)

	huma.Register(api, huma.Operation{
		OperationID: "updateIdentityProvider",
		Method:      http.MethodPatch,
		Path:        "/api/v1/tenants/{org}/identity/providers/{alias}",
		Summary:     "Update a brokered identity provider; clientSecret rotates the secret when set (org admin only)",
		Security:    sec,
	}, h.updateBrokeredIdP)

	huma.Register(api, huma.Operation{
		OperationID: "deleteIdentityProvider",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/identity/providers/{alias}",
		Summary:     "Remove a brokered identity provider (org admin only)",
		Security:    sec,
	}, h.deleteBrokeredIdP)
}

type listBrokeredIdPsOutput struct {
	Body struct {
		Providers []types.BrokeredIdP `json:"providers"`
	}
}

func (h *Handler) listBrokeredIdPs(ctx context.Context, in *orgPathInput) (*listBrokeredIdPsOutput, error) {
	org, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin)
	if err != nil {
		return nil, err
	}
	providers, err := h.svc.ListBrokeredIdPs(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listBrokeredIdPsOutput{}
	out.Body.Providers = providers
	return out, nil
}

type claimMappingInput struct {
	Email  string `json:"email,omitempty" doc:"Claim carrying the user email (defaults to the IdP's standard mapping)"`
	Groups string `json:"groups,omitempty" doc:"Claim carrying group memberships, mapped into the tenant members group"`
}

type createBrokeredIdPInput struct {
	Org  string `path:"org"`
	Body struct {
		Alias        string            `json:"alias" minLength:"1" maxLength:"63" pattern:"^[a-z0-9][a-z0-9-]*$" doc:"URL-safe IdP alias (KC alias becomes org-<org>-<alias>)"`
		IssuerURL    string            `json:"issuerUrl" minLength:"1" doc:"OIDC issuer URL (https); discovered via the discovery endpoint"`
		ClientID     string            `json:"clientId" minLength:"1"`
		ClientSecret string            `json:"clientSecret" minLength:"1" doc:"Write-only: forwarded to Keycloak, never stored or returned"`
		ClaimMapping claimMappingInput `json:"claimMapping,omitempty"`
		DomainHints  []string          `json:"domainHints,omitempty" doc:"Org email domains used for home-IdP discovery"`
	}
}

type brokeredIdPOutput struct {
	Body struct {
		Provider types.BrokeredIdP `json:"provider"`
	}
}

func (h *Handler) createBrokeredIdP(ctx context.Context, in *createBrokeredIdPInput) (*brokeredIdPOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	id := identity(ctx)
	broker, err := h.svc.CreateBrokeredIdP(ctx, id.Subject, in.Org, &types.BrokeredIdP{
		Alias:       in.Body.Alias,
		IssuerURL:   in.Body.IssuerURL,
		ClientID:    in.Body.ClientID,
		DomainHints: in.Body.DomainHints,
		ClaimMapping: types.IdPClaimMapping{
			Email:  in.Body.ClaimMapping.Email,
			Groups: in.Body.ClaimMapping.Groups,
		},
	}, in.Body.ClientSecret)
	return brokeredIdPResult(broker, err)
}

type brokeredIdPPathInput struct {
	Org   string `path:"org"`
	Alias string `path:"alias"`
}

func (h *Handler) getBrokeredIdP(ctx context.Context, in *brokeredIdPPathInput) (*brokeredIdPOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	broker, err := h.svc.GetBrokeredIdP(ctx, in.Org, in.Alias)
	return brokeredIdPResult(broker, err)
}

type updateBrokeredIdPInput struct {
	Org   string `path:"org"`
	Alias string `path:"alias"`
	Body  struct {
		IssuerURL    *string            `json:"issuerUrl,omitempty"`
		ClientID     *string            `json:"clientId,omitempty"`
		ClientSecret *string            `json:"clientSecret,omitempty" doc:"Write-only: rotates the secret when set"`
		ClaimMapping *claimMappingInput `json:"claimMapping,omitempty"`
		DomainHints  *[]string          `json:"domainHints,omitempty"`
	}
}

func (h *Handler) updateBrokeredIdP(ctx context.Context, in *updateBrokeredIdPInput) (*brokeredIdPOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	broker, err := h.svc.GetBrokeredIdP(ctx, in.Org, in.Alias)
	if err != nil {
		return brokeredIdPResult(nil, err)
	}
	if in.Body.IssuerURL != nil {
		broker.IssuerURL = *in.Body.IssuerURL
	}
	if in.Body.ClientID != nil {
		broker.ClientID = *in.Body.ClientID
	}
	if in.Body.ClaimMapping != nil {
		broker.ClaimMapping = types.IdPClaimMapping{
			Email:  in.Body.ClaimMapping.Email,
			Groups: in.Body.ClaimMapping.Groups,
		}
	}
	if in.Body.DomainHints != nil {
		broker.DomainHints = *in.Body.DomainHints
	}
	secret := ""
	if in.Body.ClientSecret != nil {
		secret = *in.Body.ClientSecret
	}
	id := identity(ctx)
	if err := h.svc.UpdateBrokeredIdP(ctx, id.Subject, in.Org, broker, secret); err != nil {
		return brokeredIdPResult(nil, err)
	}
	return brokeredIdPResult(broker, nil)
}

func (h *Handler) deleteBrokeredIdP(ctx context.Context, in *brokeredIdPPathInput) (*struct{}, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	id := identity(ctx)
	err := h.svc.DeleteBrokeredIdP(ctx, id.Subject, in.Org, in.Alias)
	switch {
	case errors.Is(err, ErrBrokerNotFound):
		return nil, huma.Error404NotFound("identity provider not found")
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	return nil, nil
}

func brokeredIdPResult(broker *types.BrokeredIdP, err error) (*brokeredIdPOutput, error) {
	switch {
	case errors.Is(err, ErrBrokerNotFound):
		return nil, huma.Error404NotFound("identity provider not found")
	case errors.Is(err, ErrBrokerExists):
		return nil, huma.Error409Conflict("organization already has an identity provider")
	case errors.Is(err, ErrDomainTaken):
		return nil, huma.Error409Conflict("domain already used by another organization")
	case errors.Is(err, ErrInvalidDomain):
		return nil, huma.Error400BadRequest(err.Error())
	case errors.Is(err, ErrOrgNotFound):
		return nil, huma.Error404NotFound("organization not found")
	case err != nil:
		return nil, err
	}
	out := &brokeredIdPOutput{}
	out.Body.Provider = *broker
	return out, nil
}
