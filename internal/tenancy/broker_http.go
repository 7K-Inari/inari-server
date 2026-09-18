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

	// UI-compat adapter (singular paths): the console's hand-written IdP
	// client (inari-ui/src/api/idp.ts) addresses one IdP per org at
	// /identity/provider[...]; these routes delegate to the same broker
	// service over the org's single provider (v1). Contract pinned to that
	// client — change only together with it (live 404 incident 2026-09-16).
	huma.Register(api, huma.Operation{
		OperationID: "getIdentityProviderCompat",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/identity/provider",
		Summary:     "Get the tenant's single identity provider, or null (UI contract; org admin only)",
		Security:    sec,
	}, h.getProviderCompat)

	huma.Register(api, huma.Operation{
		OperationID: "putIdentityProviderCompat",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/identity/provider",
		Summary:     "Create-or-replace the tenant's single identity provider (UI contract; org admin only)",
		Security:    sec,
	}, h.putProviderCompat)

	huma.Register(api, huma.Operation{
		OperationID: "deleteIdentityProviderCompat",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/identity/provider",
		Summary:     "Delete the tenant's single identity provider (UI contract; org admin only)",
		Security:    sec,
	}, h.deleteProviderCompat)

	huma.Register(api, huma.Operation{
		OperationID: "putProviderDomainsCompat",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/identity/provider/domains",
		Summary:     "Replace the provider's login-routing domain hints (UI contract; org admin only)",
		Security:    sec,
	}, h.putProviderDomainsCompat)

	huma.Register(api, huma.Operation{
		OperationID: "rotateProviderSecretCompat",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/identity/provider/secret:rotate",
		Summary:     "Rotate the provider's write-only client secret (UI contract; org admin only)",
		Security:    sec,
	}, h.rotateProviderSecretCompat)
}

// singleProvider returns the org's only brokered IdP (v1: at most one).
func (h *Handler) singleProvider(ctx context.Context, slug string) (*types.BrokeredIdP, error) {
	org, err := h.authorizeOrg(ctx, slug, authz.RelationAdmin)
	if err != nil {
		return nil, err
	}
	providers, err := h.svc.ListBrokeredIdPs(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	if len(providers) == 0 {
		return nil, ErrBrokerNotFound
	}
	return &providers[0], nil
}

type providerCompatOutput struct {
	Body struct {
		Provider *types.BrokeredIdP `json:"provider"`
	}
}

func (h *Handler) getProviderCompat(ctx context.Context, in *orgPathInput) (*providerCompatOutput, error) {
	out := &providerCompatOutput{}
	broker, err := h.singleProvider(ctx, in.Org)
	if errors.Is(err, ErrBrokerNotFound) {
		return out, nil // 200 {"provider": null} — the UI renders the empty form
	}
	if err != nil {
		return nil, err
	}
	out.Body.Provider = broker
	return out, nil
}

type putProviderCompatInput struct {
	Org  string `path:"org"`
	Body struct {
		Alias        string            `json:"alias" minLength:"1" maxLength:"63" pattern:"^[a-z0-9][a-z0-9-]*$"`
		IssuerURL    string            `json:"issuerUrl" minLength:"1"`
		ClientID     string            `json:"clientId" minLength:"1"`
		ClientSecret string            `json:"clientSecret,omitempty" doc:"Write-only: required on create, rotates on update when set"`
		ClaimMapping claimMappingInput `json:"claimMapping,omitempty"`
		DomainHints  []string          `json:"domainHints,omitempty"`
	}
}

func (h *Handler) putProviderCompat(ctx context.Context, in *putProviderCompatInput) (*providerCompatOutput, error) {
	if _, err := h.authorizeOrg(ctx, in.Org, authz.RelationAdmin); err != nil {
		return nil, err
	}
	id := identity(ctx)
	desired := &types.BrokeredIdP{
		Alias:       in.Body.Alias,
		IssuerURL:   in.Body.IssuerURL,
		ClientID:    in.Body.ClientID,
		DomainHints: in.Body.DomainHints,
		ClaimMapping: types.IdPClaimMapping{
			Email:  in.Body.ClaimMapping.Email,
			Groups: in.Body.ClaimMapping.Groups,
		},
	}
	existing, err := h.singleProvider(ctx, in.Org)
	switch {
	case errors.Is(err, ErrBrokerNotFound):
		if in.Body.ClientSecret == "" {
			return nil, huma.Error422UnprocessableEntity("clientSecret is required when creating an identity provider")
		}
		broker, cerr := h.svc.CreateBrokeredIdP(ctx, id.Subject, in.Org, desired, in.Body.ClientSecret)
		return providerCompatResult(broker, cerr)
	case err != nil:
		return nil, err
	}
	desired.OrgID = existing.OrgID
	desired.CreatedAt = existing.CreatedAt
	if err := h.svc.UpdateBrokeredIdP(ctx, id.Subject, in.Org, desired, in.Body.ClientSecret); err != nil {
		return providerCompatResult(nil, err)
	}
	return providerCompatResult(desired, nil)
}

func (h *Handler) deleteProviderCompat(ctx context.Context, in *orgPathInput) (*struct{}, error) {
	broker, err := h.singleProvider(ctx, in.Org)
	if err != nil {
		return providerCompatNotFound(err)
	}
	id := identity(ctx)
	if err := h.svc.DeleteBrokeredIdP(ctx, id.Subject, in.Org, broker.Alias); err != nil {
		return providerCompatNotFound(err)
	}
	return nil, nil
}

type putProviderDomainsInput struct {
	Org  string `path:"org"`
	Body struct {
		DomainHints []string `json:"domainHints"`
	}
}

func (h *Handler) putProviderDomainsCompat(ctx context.Context, in *putProviderDomainsInput) (*providerCompatOutput, error) {
	broker, err := h.singleProvider(ctx, in.Org)
	if err != nil {
		return providerCompatNotFoundTyped(err)
	}
	broker.DomainHints = in.Body.DomainHints
	id := identity(ctx)
	if err := h.svc.UpdateBrokeredIdP(ctx, id.Subject, in.Org, broker, ""); err != nil {
		return providerCompatResult(nil, err)
	}
	return providerCompatResult(broker, nil)
}

type rotateProviderSecretInput struct {
	Org  string `path:"org"`
	Body struct {
		ClientSecret string `json:"clientSecret" minLength:"1"`
	}
}

func (h *Handler) rotateProviderSecretCompat(ctx context.Context, in *rotateProviderSecretInput) (*struct{}, error) {
	broker, err := h.singleProvider(ctx, in.Org)
	if err != nil {
		return providerCompatNotFound(err)
	}
	id := identity(ctx)
	if err := h.svc.UpdateBrokeredIdP(ctx, id.Subject, in.Org, broker, in.Body.ClientSecret); err != nil {
		return providerCompatNotFound(err)
	}
	return nil, nil
}

func providerCompatNotFound(err error) (*struct{}, error) {
	if errors.Is(err, ErrBrokerNotFound) {
		return nil, huma.Error404NotFound("identity provider not found")
	}
	return nil, err
}

func providerCompatNotFoundTyped(err error) (*providerCompatOutput, error) {
	if errors.Is(err, ErrBrokerNotFound) {
		return nil, huma.Error404NotFound("identity provider not found")
	}
	return nil, err
}

func providerCompatResult(broker *types.BrokeredIdP, err error) (*providerCompatOutput, error) {
	switch {
	case errors.Is(err, ErrBrokerNotFound):
		return nil, huma.Error404NotFound("identity provider not found")
	case errors.Is(err, ErrBrokerExists):
		return nil, huma.Error409Conflict("organization already has an identity provider")
	case errors.Is(err, ErrDomainTaken):
		return nil, huma.Error409Conflict("domain already used by another organization")
	case errors.Is(err, ErrInvalidDomain):
		return nil, huma.Error422UnprocessableEntity(err.Error())
	case err != nil:
		return nil, err
	}
	out := &providerCompatOutput{}
	out.Body.Provider = broker
	return out, nil
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
