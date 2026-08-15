// HTTP handlers for the orchestrator module (plan §5.2 Orchestrator).
package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TenantResolver resolves a tenant slug to its record (tenancy.Service).
type TenantResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

// Handler exposes the orchestrator REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the orchestrator API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "deployCatalogItem",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/deploys",
		Summary:     "Deploy a catalog item to a cluster",
		Security:    httpserver.SecurityRequirement(),
	}, h.deploy)

	huma.Register(api, huma.Operation{
		OperationID: "upgradeInstance",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/instances/{id}/upgrade",
		Summary:     "One-click upgrade of an instance to a newer catalog version",
		Security:    httpserver.SecurityRequirement(),
	}, h.upgrade)

	huma.Register(api, huma.Operation{
		OperationID: "instanceDiff",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/instances/{id}/diff",
		Summary:     "Diff preview data for an upgrade",
		Security:    httpserver.SecurityRequirement(),
	}, h.diff)

	huma.Register(api, huma.Operation{
		OperationID: "setTenantGitConfig",
		Method:      http.MethodPut,
		Path:        "/api/v1/tenants/{org}/git-config",
		Summary:     "Set the tenant state repo + commit policy (platform engineer)",
		Security:    httpserver.SecurityRequirement(),
	}, h.setGitConfig)

	huma.Register(api, huma.Operation{
		OperationID: "getTenantGitConfig",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/git-config",
		Summary:     "Read the tenant state repo config",
		Security:    httpserver.SecurityRequirement(),
	}, h.getGitConfig)
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

type deployInput struct {
	Org  string `path:"org"`
	Body struct {
		ItemID    string          `json:"itemId" minLength:"1"`
		ClusterID string          `json:"clusterId" minLength:"1"`
		Version   string          `json:"version,omitempty"`
		Channel   string          `json:"channel,omitempty"`
		Name      string          `json:"name,omitempty"`
		Namespace string          `json:"namespace,omitempty"`
		OwnerTeam string          `json:"ownerTeam,omitempty"`
		Spec      json.RawMessage `json:"spec"`
	}
}

type deployOutput struct {
	Body struct {
		Deploy DeployResult `json:"deploy"`
	}
}

func (h *Handler) deploy(ctx context.Context, in *deployInput) (*deployOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeveloper)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.Deploy(ctx, DeployRequest{
		OrgID: org.ID, ClusterID: in.Body.ClusterID, ItemID: in.Body.ItemID,
		Version: in.Body.Version, Channel: in.Body.Channel, Name: in.Body.Name,
		Namespace: in.Body.Namespace, OwnerTeam: in.Body.OwnerTeam,
		Spec: in.Body.Spec, Requester: "user:" + id.Subject,
	})
	if errors.Is(err, ErrNoGitConfig) {
		return nil, huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, ErrClusterNotActive) {
		return nil, huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, catalog.ErrItemNotFound) {
		return nil, huma.Error404NotFound("catalog item not found")
	}
	if err != nil {
		return nil, err
	}
	out := &deployOutput{}
	out.Body.Deploy = *res
	return out, nil
}

type instancePathInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

type upgradeInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		ToVersion string `json:"toVersion" minLength:"1"`
	}
}

func (h *Handler) upgrade(ctx context.Context, in *upgradeInput) (*deployOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeveloper)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.Upgrade(ctx, org.ID, in.ID, in.Body.ToVersion, "user:"+id.Subject)
	if errors.Is(err, inventory.ErrInstanceNotFound) {
		return nil, huma.Error404NotFound("instance not found")
	}
	if err != nil {
		return nil, err
	}
	out := &deployOutput{}
	out.Body.Deploy = *res
	return out, nil
}

type diffInput struct {
	Org       string `path:"org"`
	ID        string `path:"id"`
	ToVersion string `query:"to" doc:"Target version" required:"true"`
}

type diffOutput struct {
	Body struct {
		Diff DiffPreview `json:"diff"`
	}
}

func (h *Handler) diff(ctx context.Context, in *diffInput) (*diffOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	d, err := h.svc.DiffPreview(ctx, org.ID, in.ID, in.ToVersion)
	if errors.Is(err, inventory.ErrInstanceNotFound) {
		return nil, huma.Error404NotFound("instance not found")
	}
	if err != nil {
		return nil, err
	}
	out := &diffOutput{}
	out.Body.Diff = *d
	return out, nil
}

type gitConfigInput struct {
	Org  string `path:"org"`
	Body struct {
		Repo         string `json:"repo" minLength:"1" doc:"owner/name or https URL of the <tenant>-inari-state repo"`
		CommitPolicy string `json:"commitPolicy" enum:"direct,pull_request"`
		BaseBranch   string `json:"baseBranch,omitempty"`
	}
}

type gitConfigOutput struct {
	Body struct {
		Config types.TenantGitConfig `json:"config"`
	}
}

func (h *Handler) setGitConfig(ctx context.Context, in *gitConfigInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationPlatformEngineer)
	if err != nil {
		return nil, err
	}
	policy := types.CommitPolicy(in.Body.CommitPolicy)
	if policy == "" {
		policy = types.CommitPolicyDirect
	}
	branch := in.Body.BaseBranch
	if branch == "" {
		branch = "main"
	}
	return nil, h.svc.SetGitConfig(ctx, "user:"+id.Subject, &types.TenantGitConfig{
		OrgID: org.ID, Repo: in.Body.Repo, CommitPolicy: policy, BaseBranch: branch,
	})
}

func (h *Handler) getGitConfig(ctx context.Context, in *instancePathInput) (*gitConfigOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationViewer)
	if err != nil {
		return nil, err
	}
	cfg, err := h.svc.GetGitConfig(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, huma.Error404NotFound("git config not set")
	}
	out := &gitConfigOutput{}
	out.Body.Config = *cfg
	return out, nil
}
