// HTTP handlers for the cluster registry module.
package clusterregistry

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/fleetmanager"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/kubeproxy"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TenantResolver resolves a tenant slug to its record (tenancy.Service).
type TenantResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

// Handler exposes the cluster registry REST surface.
type Handler struct {
	svc       *Service
	tenants   TenantResolver
	authz     authz.Authorizer
	caps      CapabilitiesLister
	issuerURL string
	// Platform-declared agent compatibility policy (INARI_AGENT_* envs);
	// when all three are empty the agentCompat block is omitted from
	// responses (pre-policy behavior).
	agentSupportedRange string
	agentCurrent        string
	agentRecommended    string
	// Kubectl gateway (plan §7.2), wired via WithKubectlGateway.
	kubeproxyPublicURL string
	accessFlags        AccessFlagEvaluator
	tunnelLiveness     TunnelLiveness
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

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer, caps CapabilitiesLister) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az, caps: caps}
}

// WithAccessInfo wires the platform OIDC issuer URL used by the cluster
// access-info endpoint (kubectl access via kubelogin, plan §5.4, §7.2).
func (h *Handler) WithAccessInfo(issuerURL string) *Handler {
	h.issuerURL = issuerURL
	return h
}

// AccessFlagEvaluator is the kubectl_access.enabled flag seam (static
// evaluator today; task f368d08b delivers the flag system).
type AccessFlagEvaluator interface {
	KubectlAccessEnabled(ctx context.Context) bool
}

// TunnelLiveness reports tunnel-agent session availability (implemented by
// kubeproxy.LivenessReader over the heartbeat table).
type TunnelLiveness interface {
	Available(ctx context.Context, clusterID string) (bool, error)
}

// WithKubectlGateway wires the kubectl-gateway fields of access-info and
// the kubeconfig render endpoint (plan §7.2): the kubeproxy public base
// URL (empty = gateway not deployed), the feature flag, and the
// tunnel-agent liveness reader. All nil/empty-safe.
func (h *Handler) WithKubectlGateway(publicURL string, flags AccessFlagEvaluator, liveness TunnelLiveness) *Handler {
	h.kubeproxyPublicURL = publicURL
	h.accessFlags = flags
	h.tunnelLiveness = liveness
	return h
}

// kubectlAccessEnabled evaluates the flag, defaulting to enabled when no
// evaluator is wired (pre-gateway deployments).
func (h *Handler) kubectlAccessEnabled(ctx context.Context) bool {
	if h.accessFlags == nil {
		return true
	}
	return h.accessFlags.KubectlAccessEnabled(ctx)
}

// WithAgentCompat wires the platform-declared agent compatibility policy
// (supported range, legacy current version, recommended version) so cluster
// responses carry the computed agentCompat assessment.
func (h *Handler) WithAgentCompat(supportedRange, current, recommended string) *Handler {
	h.agentSupportedRange = supportedRange
	h.agentCurrent = current
	h.agentRecommended = recommended
	return h
}

// enrichAgentCompat populates the computed agentCompat assessment on a
// cluster response; a no-op when the platform declares no agent
// compatibility policy (responses stay byte-identical to pre-policy).
func (h *Handler) enrichAgentCompat(c *types.Cluster) {
	if h.agentSupportedRange == "" && h.agentCurrent == "" && h.agentRecommended == "" {
		return
	}
	c.AgentCompat = &types.AgentCompatStatus{
		Supported:          fleetmanager.AgentSupported(h.agentSupportedRange, h.agentCurrent, c.AgentVersion),
		RecommendedVersion: h.agentRecommended,
		UpgradeAvailable:   fleetmanager.UpgradeAvailable(h.agentRecommended, c.AgentVersion),
	}
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
		OperationID: "getClusterAccessInfo",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/access-info",
		Summary:     "OIDC access info for building a kubelogin kubeconfig (no secrets, no API URL)",
		Security:    httpserver.SecurityRequirement(),
	}, h.getAccessInfo)

	huma.Register(api, huma.Operation{
		OperationID: "getClusterKubeconfig",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/kubeconfig",
		Summary:     "Render a secret-free kubeconfig (gateway or direct mode) for download",
		Security:    httpserver.SecurityRequirement(),
	}, h.getKubeconfig)

	huma.Register(api, huma.Operation{
		OperationID: "issueRegistrationToken",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/tokens",
		Summary:     "Issue a one-time TTL'd registration token",
		Security:    httpserver.SecurityRequirement(),
	}, h.issueToken)

	huma.Register(api, huma.Operation{
		OperationID: "listRegistrationTokens",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/tokens",
		Summary:     "List active (unconsumed, unexpired) registration tokens",
		Security:    httpserver.SecurityRequirement(),
	}, h.listTokens)

	huma.Register(api, huma.Operation{
		OperationID: "revokeRegistrationToken",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/tokens/{tokenId}",
		Summary:     "Revoke (burn) a registration token (org admin only)",
		Security:    httpserver.SecurityRequirement(),
	}, h.revokeToken)

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
		OperationID: "cordonCluster",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/cordon",
		Summary:     "Cordon a cluster (blocks new deploys; workloads keep running)",
		Security:    httpserver.SecurityRequirement(),
	}, h.cordonCluster)

	huma.Register(api, huma.Operation{
		OperationID: "uncordonCluster",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/uncordon",
		Summary:     "Uncordon a cluster (returns it to service)",
		Security:    httpserver.SecurityRequirement(),
	}, h.uncordonCluster)

	huma.Register(api, huma.Operation{
		OperationID: "decommissionCluster",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/clusters/{id}/decommission",
		Summary:     "Decommission a cluster (ownership-checked drain, identity revocation, archived audit)",
		Security:    httpserver.SecurityRequirement(),
	}, h.decommissionCluster)

	huma.Register(api, huma.Operation{
		OperationID: "deleteCluster",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/clusters/{id}",
		Summary:     "Cancel a pending cluster registration (409 once registered)",
		Security:    httpserver.SecurityRequirement(),
	}, h.deleteCluster)

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
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationClustersRegister)
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
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	clusters, err := h.svc.ListClusters(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	for i := range clusters {
		h.enrichAgentCompat(&clusters[i])
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
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
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
	h.enrichAgentCompat(c)
	out := &clusterOutput{}
	out.Body.Cluster = *c
	return out, nil
}

type accessInfoOutput struct {
	Body struct {
		AccessInfo types.ClusterAccessInfo `json:"accessInfo"`
	}
}

// getAccessInfo returns the kubelogin kubeconfig inputs for a cluster. The
// per-tenant public client org-<slug>-kubectl is provisioned by tenancy
// (EnsureKubectlClient); the API-server URL is never returned — the hub
// doesn't know it (pull-only).
func (h *Handler) getAccessInfo(ctx context.Context, in *clusterPathInput) (*accessInfoOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	if err := h.requireOrgCluster(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	if h.issuerURL == "" {
		return nil, huma.Error500InternalServerError("OIDC issuer URL is not configured on the control plane")
	}
	out := &accessInfoOutput{}
	info := types.ClusterAccessInfo{
		IssuerURL:            h.issuerURL,
		KubectlClientID:      tenancy.KubectlClientID(org.Slug),
		Audience:             "kubernetes",
		Organization:         org.Slug,
		KubectlAccessEnabled: h.kubectlAccessEnabled(ctx),
	}
	if h.kubeproxyPublicURL != "" {
		info.ProxyURL = kubeproxy.ProxyURL(h.kubeproxyPublicURL, org.Slug, in.ID)
	}
	if h.tunnelLiveness != nil {
		avail, err := h.tunnelLiveness.Available(ctx, in.ID)
		if err != nil {
			// Liveness is advisory — never fail the endpoint on it.
			avail = false
		}
		info.TunnelAvailable = avail
	}
	info.TunnelUnavailableReason = h.tunnelUnavailableReason(ctx, info)
	out.Body.AccessInfo = info
	return out, nil
}

// tunnelUnavailableReason explains a false TunnelAvailable (empty when the
// tunnel is usable).
func (h *Handler) tunnelUnavailableReason(ctx context.Context, info types.ClusterAccessInfo) string {
	switch {
	case !info.KubectlAccessEnabled:
		return "kubectl access is disabled by platform policy"
	case info.TunnelAvailable:
		return ""
	case h.kubeproxyPublicURL == "":
		return "kubectl gateway is not deployed on this platform"
	default:
		return "no tunnel agent is connected for this cluster — upgrade the inari-agent chart to a version with kubectl tunnel support"
	}
}

type kubeconfigInput struct {
	Org       string `path:"org"`
	ID        string `path:"id"`
	Mode      string `query:"mode" enum:"gateway,direct" default:"gateway" doc:"gateway points at inari-kubeproxy; direct needs a server URL"`
	GrantType string `query:"grantType" enum:"authcode,device-code" default:"device-code" doc:"kubelogin login flow"`
	Server    string `query:"server" doc:"Apiserver URL for direct mode"`
}

type kubeconfigOutput struct {
	ContentType string `header:"Content-Type"`
	Body        []byte
}

// getKubeconfig renders the canonical secret-free exec-credential
// kubeconfig (plan §7.2) for download — the same renderer the CLI mirrors.
func (h *Handler) getKubeconfig(ctx context.Context, in *kubeconfigInput) (*kubeconfigOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	if err := h.requireOrgCluster(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	if !h.kubectlAccessEnabled(ctx) {
		return nil, huma.NewError(http.StatusGone, "kubectl access is disabled by platform policy")
	}
	if h.issuerURL == "" {
		return nil, huma.Error500InternalServerError("OIDC issuer URL is not configured on the control plane")
	}
	var serverURL string
	if in.Mode == "direct" {
		if in.Server == "" {
			return nil, huma.Error422UnprocessableEntity("direct mode requires the server query parameter")
		}
		serverURL = in.Server
	} else {
		if h.kubeproxyPublicURL == "" {
			return nil, huma.NewError(http.StatusServiceUnavailable, "kubectl gateway is not deployed on this platform")
		}
		serverURL = kubeproxy.ProxyURL(h.kubeproxyPublicURL, org.Slug, in.ID)
	}
	doc, err := kubeproxy.RenderKubeconfig(kubeproxy.KubeconfigOptions{
		Name:      org.Slug + "-" + in.ID,
		ServerURL: serverURL,
		IssuerURL: h.issuerURL,
		ClientID:  tenancy.KubectlClientID(org.Slug),
		GrantType: in.GrantType,
	})
	if err != nil {
		return nil, huma.Error422UnprocessableEntity(err.Error())
	}
	return &kubeconfigOutput{ContentType: "application/yaml", Body: []byte(doc)}, nil
}

type tokenOutput struct {
	Body struct {
		Token     string                  `json:"token" doc:"Plaintext bootstrap token, returned once"`
		Record    types.RegistrationToken `json:"record"`
		ExpiresAt string                  `json:"expiresAt"`
	}
}

func (h *Handler) issueToken(ctx context.Context, in *clusterPathInput) (*tokenOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationClustersRegister)
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

type listTokensOutput struct {
	Body struct {
		Tokens []types.RegistrationToken `json:"tokens"`
	}
}

func (h *Handler) listTokens(ctx context.Context, in *clusterPathInput) (*listTokensOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	if err := h.requireOrgCluster(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	tokens, err := h.svc.ListTokens(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	out := &listTokensOutput{}
	out.Body.Tokens = tokens
	return out, nil
}

type revokeTokenInput struct {
	Org     string `path:"org"`
	ID      string `path:"id"`
	TokenID string `path:"tokenId"`
}

func (h *Handler) revokeToken(ctx context.Context, in *revokeTokenInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationClustersRegister)
	if err != nil {
		return nil, err
	}
	if err := h.requireOrgCluster(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	err = h.svc.RevokeToken(ctx, id.Subject, in.ID, in.TokenID)
	if errors.Is(err, ErrTokenNotFound) {
		return nil, huma.Error404NotFound("registration token not found")
	}
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (h *Handler) approveCluster(ctx context.Context, in *clusterPathInput) (*clusterOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationClustersRegister)
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
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationClustersRegister)
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

func (h *Handler) deleteCluster(ctx context.Context, in *clusterPathInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationClustersRegister)
	if err != nil {
		return nil, err
	}
	if err := h.requireOrgCluster(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	if err := h.svc.DeleteCluster(ctx, id.Subject, in.ID); errors.Is(err, ErrClusterNotPendingDeletion) {
		return nil, huma.Error409Conflict(err.Error())
	} else if err != nil {
		return nil, err
	}
	return nil, nil
}

func (h *Handler) cordonCluster(ctx context.Context, in *clusterPathInput) (*clusterOutput, error) {
	return h.lifecycle(ctx, in, h.svc.CordonCluster)
}

func (h *Handler) uncordonCluster(ctx context.Context, in *clusterPathInput) (*clusterOutput, error) {
	return h.lifecycle(ctx, in, h.svc.UncordonCluster)
}

type decommissionInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		Force bool `json:"force,omitempty" doc:"Drain even when non-Inari-managed resources exist (§10 override)"`
	}
}

type decommissionOutput struct {
	Body struct {
		Cluster            types.Cluster `json:"cluster"`
		DrainedInstanceIDs []string      `json:"drainedInstanceIds"`
	}
}

func (h *Handler) decommissionCluster(ctx context.Context, in *decommissionInput) (*decommissionOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationClustersRegister)
	if err != nil {
		return nil, err
	}
	if err := h.requireOrgCluster(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	c, drained, err := h.svc.DecommissionCluster(ctx, id.Subject, in.ID, in.Body.Force)
	if errors.Is(err, ErrSharedResources) {
		return nil, huma.Error409Conflict("cluster holds non-Inari-managed resources; re-run with force to override (§10)")
	}
	if errors.Is(err, ErrInvalidTransition) {
		return nil, huma.Error409Conflict(err.Error())
	}
	if err != nil {
		return nil, err
	}
	out := &decommissionOutput{}
	out.Body.Cluster = *c
	out.Body.DrainedInstanceIDs = drained
	return out, nil
}

// lifecycle runs a simple state-transition endpoint (cordon/uncordon).
func (h *Handler) lifecycle(ctx context.Context, in *clusterPathInput, fn func(context.Context, string, string) (*types.Cluster, error)) (*clusterOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationClustersRegister)
	if err != nil {
		return nil, err
	}
	if err := h.requireOrgCluster(ctx, org.ID, in.ID); err != nil {
		return nil, err
	}
	c, err := fn(ctx, id.Subject, in.ID)
	if errors.Is(err, ErrInvalidTransition) {
		return nil, huma.Error409Conflict(err.Error())
	}
	if err != nil {
		return nil, err
	}
	out := &clusterOutput{}
	out.Body.Cluster = *c
	return out, nil
}

type listCapabilitiesOutput struct {
	Body struct {
		Capabilities []types.Capability `json:"capabilities"`
	}
}

func (h *Handler) listCapabilities(ctx context.Context, in *clusterPathInput) (*listCapabilitiesOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
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
