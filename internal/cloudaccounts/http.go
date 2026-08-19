// HTTP handlers for the cloud accounts module (plan §5.7).
package cloudaccounts

import (
	"context"
	"errors"
	"fmt"
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

// ClusterResolver loads a cluster for ProviderConfig rendering (satisfied by
// clusterregistry.Service).
type ClusterResolver interface {
	GetCluster(ctx context.Context, id string) (*types.Cluster, error)
}

// Handler exposes the cloud accounts REST surface.
type Handler struct {
	svc      *Service
	tenants  TenantResolver
	clusters ClusterResolver
	authz    authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, clusters ClusterResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, clusters: clusters, authz: az}
}

// RegisterRoutes mounts the cloud accounts API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "registerCloudAccount",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/cloud-accounts",
		Summary:     "Register a cloud account (role ARN + external ID, never keys)",
		Security:    httpserver.SecurityRequirement(),
	}, h.register)

	huma.Register(api, huma.Operation{
		OperationID: "listCloudAccounts",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/cloud-accounts",
		Summary:     "List cloud accounts of a tenant",
		Security:    httpserver.SecurityRequirement(),
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID: "getCloudAccount",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/cloud-accounts/{id}",
		Summary:     "Get a cloud account",
		Security:    httpserver.SecurityRequirement(),
	}, h.get)

	huma.Register(api, huma.Operation{
		OperationID: "validateCloudAccount",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/cloud-accounts/{id}/validate",
		Summary:     "Run the STS AssumeRole dry-run against the registered role",
		Security:    httpserver.SecurityRequirement(),
	}, h.validate)

	huma.Register(api, huma.Operation{
		OperationID: "deregisterCloudAccount",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/cloud-accounts/{id}",
		Summary:     "Delete the control-plane record (AWS-side role deletion is tenant-owned)",
		Security:    httpserver.SecurityRequirement(),
	}, h.deregister)

	huma.Register(api, huma.Operation{
		OperationID: "renderCloudAccountProviderConfig",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/cloud-accounts/{id}/providerconfig",
		Summary:     "Render the Crossplane ProviderConfig manifest for a cluster",
		Security:    httpserver.SecurityRequirement(),
	}, h.providerConfig)
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

type registerInput struct {
	Org  string `path:"org"`
	Body struct {
		Provider   string `json:"provider,omitempty" doc:"Cloud provider (aws)"`
		AccountID  string `json:"accountId" doc:"12-digit AWS account ID"`
		RoleARN    string `json:"roleArn" doc:"arn:aws:iam::<acct>:role/<name>"`
		ExternalID string `json:"externalId,omitempty"`
		IssuerURL  string `json:"issuerUrl,omitempty"`
		RunContext string `json:"runContext,omitempty" doc:"tenant (default) | platform"`
	}
}

type accountOutput struct {
	Body struct {
		Account types.CloudAccount `json:"account"`
	}
}

func (h *Handler) register(ctx context.Context, in *registerInput) (*accountOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	a, err := h.svc.Register(ctx, id.Subject, org.ID, RegisterInput{
		Provider:   in.Body.Provider,
		AccountID:  in.Body.AccountID,
		RoleARN:    in.Body.RoleARN,
		ExternalID: in.Body.ExternalID,
		IssuerURL:  in.Body.IssuerURL,
		RunContext: in.Body.RunContext,
	})
	if errors.Is(err, ErrInvalidInput) {
		return nil, huma.Error422UnprocessableEntity(err.Error())
	}
	if errors.Is(err, ErrAlreadyRegistered) {
		return nil, huma.Error409Conflict("cloud account already registered for this tenant")
	}
	if err != nil {
		return nil, err
	}
	out := &accountOutput{}
	out.Body.Account = *a
	return out, nil
}

type orgPathInput struct {
	Org string `path:"org" doc:"Tenant slug"`
}

type listAccountsOutput struct {
	Body struct {
		Accounts []types.CloudAccount `json:"accounts"`
	}
}

func (h *Handler) list(ctx context.Context, in *orgPathInput) (*listAccountsOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	accounts, err := h.svc.List(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listAccountsOutput{}
	out.Body.Accounts = accounts
	return out, nil
}

type accountPathInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) get(ctx context.Context, in *accountPathInput) (*accountOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	// Coarse org-scoped check: the account must belong to the path org
	// (service enforces); an object-level OpenFGA Check on
	// authz.CloudAccountObject is equivalent here because cloud_account
	// relations derive from the parent org (authz model v1).
	a, err := h.svc.Get(ctx, org.ID, in.ID)
	if errors.Is(err, ErrNotFound) {
		return nil, huma.Error404NotFound("cloud account not found")
	}
	if err != nil {
		return nil, err
	}
	out := &accountOutput{}
	out.Body.Account = *a
	return out, nil
}

func (h *Handler) validate(ctx context.Context, in *accountPathInput) (*accountOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	a, err := h.svc.Validate(ctx, id.Subject, org.ID, in.ID)
	if errors.Is(err, ErrNotFound) {
		return nil, huma.Error404NotFound("cloud account not found")
	}
	if errors.Is(err, ErrValidationUnavailable) {
		return nil, huma.Error409Conflict("sts validation unavailable: platform has no AWS token source")
	}
	if err != nil {
		return nil, err
	}
	out := &accountOutput{}
	out.Body.Account = *a
	return out, nil
}

func (h *Handler) deregister(ctx context.Context, in *accountPathInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	if err := h.svc.Deregister(ctx, id.Subject, org.ID, in.ID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, huma.Error404NotFound("cloud account not found")
		}
		return nil, err
	}
	return nil, nil
}

type providerConfigInput struct {
	Org       string `path:"org"`
	ID        string `path:"id"`
	ClusterID string `query:"clusterId" required:"true" doc:"Cluster to render the ProviderConfig for"`
}

type manifestOutput struct {
	ContentType string `header:"Content-Type"`
	Body        []byte
}

func (h *Handler) providerConfig(ctx context.Context, in *providerConfigInput) (*manifestOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	a, err := h.svc.Get(ctx, org.ID, in.ID)
	if errors.Is(err, ErrNotFound) {
		return nil, huma.Error404NotFound("cloud account not found")
	}
	if err != nil {
		return nil, err
	}
	if a.State != types.CloudAccountStateActive {
		return nil, huma.Error422UnprocessableEntity(
			fmt.Sprintf("cloud account is %s; validate the trust before materializing a ProviderConfig", a.State))
	}
	if h.clusters == nil {
		return nil, huma.Error501NotImplemented("cluster resolver not configured")
	}
	c, err := h.clusters.GetCluster(ctx, in.ClusterID)
	if err != nil {
		return nil, huma.Error404NotFound("cluster not found")
	}
	if c.OrgID != org.ID {
		return nil, huma.Error404NotFound("cluster not found")
	}
	manifest, err := RenderProviderConfig(a, c)
	if err != nil {
		return nil, huma.Error422UnprocessableEntity(err.Error())
	}
	return &manifestOutput{ContentType: "application/yaml", Body: manifest}, nil
}
