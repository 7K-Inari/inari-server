// HTTP handlers for the cluster registry module.
package clusterregistry

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

// Handler exposes the cluster registry REST surface.
type Handler struct {
	svc      *Service
	tenants  TenantResolver
	authz    authz.Authorizer
	manifest ManifestParams
	caps     CapabilitiesLister
}

// CapabilitiesLister reads the live capabilities of a cluster (implemented
// by the capabilities module's store).
type CapabilitiesLister interface {
	List(ctx context.Context, clusterID string) ([]types.Capability, error)
}

// CapabilitiesListerFunc adapts a function to CapabilitiesLister.
type CapabilitiesListerFunc func(ctx context.Context, clusterID string) ([]types.Capability, error)

// List implements CapabilitiesLister.
func (f CapabilitiesListerFunc) List(ctx context.Context, clusterID string) ([]types.Capability, error) {
	return f(ctx, clusterID)
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer, manifest ManifestParams, caps CapabilitiesLister) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az, manifest: manifest, caps: caps}
}

// RegisterRoutes mounts the cluster API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "createCluster",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/clusters",
		Summary:     "Register a new cluster record",
		Security:    httpserver.SecurityRequirement(),
	}, h.createCluster)

	huma.Register(api, huma.Operation{
		OperationID: "listClusters",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/clusters",
		Summary:     "List clusters of a tenant with connection health",
		Security:    httpserver.SecurityRequirement(),
	}, h.listClusters)

	huma.Register(api, huma.Operation{
		OperationID: "getCluster",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/clusters/{id}",
		Summary:     "Get a cluster",
		Security:    httpserver.SecurityRequirement(),
	}, h.getCluster)

	huma.Register(api, huma.Operation{
		OperationID: "issueRegistrationToken",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/tokens",
		Summary:     "Issue a one-time TTL'd registration token",
		Security:    httpserver.SecurityRequirement(),
	}, h.issueToken)

	huma.Register(api, huma.Operation{
		OperationID: "approveCluster",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/approve",
		Summary:     "Approve cluster enrollment (double opt-in)",
		Security:    httpserver.SecurityRequirement(),
	}, h.approveCluster)

	huma.Register(api, huma.Operation{
		OperationID: "revokeCluster",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/revoke",
		Summary:     "Revoke a cluster (disables its Keycloak client)",
		Security:    httpserver.SecurityRequirement(),
	}, h.revokeCluster)

	huma.Register(api, huma.Operation{
		OperationID: "renderInstallManifest",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/install-manifest",
		Summary:     "Render the agent install manifest embedding a fresh registration token",
		Security:    httpserver.SecurityRequirement(),
	}, h.renderManifest)

	huma.Register(api, huma.Operation{
		OperationID: "listCapabilities",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/capabilities",
		Summary:     "List the live discovered capabilities of a cluster",
		Security:    httpserver.SecurityRequirement(),
	}, h.listCapabilities)
}

type createClusterInput struct {
	Org  string `path:"org"`
	Body struct {
		Name   string            `json:"name" minLength:"1" maxLength:"100"`
		Labels map[string]string `json:"labels,omitempty"`
	}
}

type clusterOutput struct {
	Body struct {
		Cluster types.Cluster `json:"cluster"`
	}
}

func (h *Handler) createCluster(ctx context.Context, in *createClusterInput) (*clusterOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	c, err := h.svc.CreateCluster(ctx, id.Subject, org.ID, in.Body.Name, in.Body.Labels)
	if errors.Is(err, ErrClusterNameTaken) {
		return nil, huma.Error409Conflict("cluster name already exists in tenant")
	}
	if err != nil {
		return nil, err
	}
	out := &clusterOutput{}
	out.Body.Cluster = *c
	return out, nil
}

type orgPathInput struct {
	Org string `path:"org" doc:"Tenant slug"`
}

type listClustersOutput struct {
	Body struct {
		Clusters []types.Cluster `json:"clusters"`
	}
}

func (h *Handler) listClusters(ctx context.Context, in *orgPathInput) (*listClustersOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	clusters, err := h.svc.ListClusters(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	out := &listClustersOutput{}
	out.Body.Clusters = clusters
	return out, nil
}

type clusterPathInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) getCluster(ctx context.Context, in *clusterPathInput) (*clusterOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	c, err := h.svc.GetCluster(ctx, in.ID)
	if errors.Is(err, ErrClusterNotFound) {
		return nil, huma.Error404NotFound("cluster not found")
	}
	if err != nil {
		return nil, err
	}
	if c.OrgID != org.ID {
		return nil, huma.Error404NotFound("cluster not found")
	}
	out := &clusterOutput{}
	out.Body.Cluster = *c
	return out, nil
}

type tokenOutput struct {
	Body struct {
		Token     string                  `json:"token" doc:"Plaintext bootstrap token, returned once"`
		Record    types.RegistrationToken `json:"record"`
		ExpiresAt string                  `json:"expiresAt"`
	}
}

func (h *Handler) issueToken(ctx context.Context, in *clusterPathInput) (*tokenOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	if err := h.requireOrgCluster(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	plaintext, rec, err := h.svc.IssueToken(ctx, id.Subject, in.ID)
	if errors.Is(err, ErrClusterRevoked) {
		return nil, huma.Error409Conflict("cluster is revoked")
	}
	if err != nil {
		return nil, err
	}
	out := &tokenOutput{}
	out.Body.Token = plaintext
	out.Body.Record = *rec
	out.Body.ExpiresAt = rec.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
	return out, nil
}

func (h *Handler) approveCluster(ctx context.Context, in *clusterPathInput) (*clusterOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	if err := h.requireOrgCluster(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	c, err := h.svc.ApproveCluster(ctx, id.Subject, in.ID)
	if errors.Is(err, ErrClusterNotPending) {
		return nil, huma.Error409Conflict("cluster is not pending approval")
	}
	if err != nil {
		return nil, err
	}
	out := &clusterOutput{}
	out.Body.Cluster = *c
	return out, nil
}

func (h *Handler) revokeCluster(ctx context.Context, in *clusterPathInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	if err := h.requireOrgCluster(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	if err := h.svc.RevokeCluster(ctx, id.Subject, in.ID); err != nil {
		return nil, err
	}
	return nil, nil
}

type manifestOutput struct {
	ContentType string `header:"Content-Type"`
	Body        []byte
}

func (h *Handler) renderManifest(ctx context.Context, in *clusterPathInput) (*manifestOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	c, err := h.svc.GetCluster(ctx, in.ID)
	if errors.Is(err, ErrClusterNotFound) || (err == nil && c.OrgID != org.ID) {
		return nil, huma.Error404NotFound("cluster not found")
	}
	if err != nil {
		return nil, err
	}
	plaintext, _, err := h.svc.IssueToken(ctx, id.Subject, in.ID)
	if err != nil {
		return nil, err
	}
	manifest, err := RenderInstallManifest(c, plaintext, h.manifest)
	if err != nil {
		return nil, err
	}
	return &manifestOutput{ContentType: "application/yaml", Body: manifest}, nil
}

type listCapabilitiesOutput struct {
	Body struct {
		Capabilities []types.Capability `json:"capabilities"`
	}
}

func (h *Handler) listCapabilities(ctx context.Context, in *clusterPathInput) (*listCapabilitiesOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	if err := h.requireOrgCluster(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	if h.caps == nil {
		return nil, huma.Error501NotImplemented("capabilities store not configured")
	}
	caps, err := h.caps.List(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	out := &listCapabilitiesOutput{}
	out.Body.Capabilities = caps
	return out, nil
}

// requireOrgCluster guards against cross-tenant object access by ID.
func (h *Handler) requireOrgCluster(ctx context.Context, orgID, clusterID string) error {
	c, err := h.svc.GetCluster(ctx, clusterID)
	if errors.Is(err, ErrClusterNotFound) {
		return huma.Error404NotFound("cluster not found")
	}
	if err != nil {
		return err
	}
	if c.OrgID != orgID {
		return huma.Error404NotFound("cluster not found")
	}
	return nil
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
