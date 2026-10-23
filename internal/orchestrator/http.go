// HTTP handlers for the orchestrator module (plan §5.2 Orchestrator).
package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	gitgithub "github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider/github"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/tenancy/gitkeys"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TenantResolver resolves a tenant slug to its record (tenancy.Service).
type TenantResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
}

// TeamLister resolves an org's teams for the repo-write enforcement check
// (tenancy.Service seam).
type TeamLister interface {
	ListTeams(ctx context.Context, orgID string) ([]types.Team, error)
}

// RepoGetter resolves one registry repo row for the enforcement check
// (inventory.Store seam via adapter).
type RepoGetter interface {
	GetGitRepo(ctx context.Context, orgID, id string) (*types.TenantGitRepo, error)
}

// InstanceGetter loads an instance for the recorded-repo enforcement check
// on mutations (inventory.Store seam via adapter).
type InstanceGetter interface {
	GetInstance(ctx context.Context, id string) (*types.ResourceInstance, error)
}

// Handler exposes the orchestrator REST surface.
type Handler struct {
	svc     *Service
	tenants TenantResolver
	authz   authz.Authorizer
	// teams/repos enable the team-repo write enforcement (Feature A,
	// decision 5b). nil teams/repos = enforcement disabled (legacy wiring,
	// single-repo orgs behave exactly as before).
	teams TeamLister
	repos RepoGetter
	// instances feeds the recorded-repo enforcement on mutations.
	instances InstanceGetter
	// allowedAPIBases allowlists tenant BYO GitHub Enterprise apiBase hosts
	// (empty: any https host).
	allowedAPIBases []string
}

func NewHandler(svc *Service, tenants TenantResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// WithRepoWriteEnforcement wires the team-repo write check (decision 5b).
func (h *Handler) WithRepoWriteEnforcement(teams TeamLister, repos RepoGetter, instances InstanceGetter) *Handler {
	h.teams, h.repos, h.instances = teams, repos, instances
	return h
}

// WithAllowedAPIBases pins the GHE hosts tenants may point BYO apps at.
func (h *Handler) WithAllowedAPIBases(bases []string) *Handler {
	h.allowedAPIBases = bases
	return h
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
		OperationID: "updateInstance",
		Method:      http.MethodPatch,
		Path:        "/api/v1/tenants/{org}/instances/{id}",
		Summary:     "Update an instance's spec (re-render at the current version)",
		Security:    httpserver.SecurityRequirement(),
	}, h.updateInstance)

	huma.Register(api, huma.Operation{
		OperationID: "deleteInstance",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/instances/{id}",
		Summary:     "Undeploy an instance (delete desired state + inventory row)",
		Security:    httpserver.SecurityRequirement(),
	}, h.deleteInstance)

	huma.Register(api, huma.Operation{
		OperationID: "rollbackInstance",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/instances/{id}/rollback",
		Summary:     "Rollback an instance to an explicit earlier catalog version",
		Security:    httpserver.SecurityRequirement(),
	}, h.rollback)

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

// enforceRepoWrite implements the team-repo write check (Feature A,
// decision 5b): platform repos are writable by any org member with
// deployments_create (already checked); team repos require settings-write
// (platform team / org admins) or membership in the owning team. An empty
// repoID (org default) skips the check — identical to pre-Feature-A
// behavior. Unknown rows read as 404.
func (h *Handler) enforceRepoWrite(ctx context.Context, id *authn.Identity, orgID, repoID string) error {
	if repoID == "" || h.teams == nil || h.repos == nil {
		return nil
	}
	row, err := h.repos.GetGitRepo(ctx, orgID, repoID)
	if errors.Is(err, inventory.ErrRepoNotFound) {
		return huma.Error404NotFound("git repo not found")
	}
	if err != nil {
		return err
	}
	if row.Scope == types.GitRepoScopePlatform {
		return nil
	}
	ok, err := h.authz.Check(ctx, authz.UserObject(id.Subject), authz.RelationTenantSettingsWrite, authz.OrgObject(orgID))
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	teams, err := h.teams.ListTeams(ctx, orgID)
	if err != nil {
		return err
	}
	for _, t := range authn.CallerTeamIDs(id, teams) {
		if t == row.TeamID {
			return nil
		}
	}
	return huma.Error403Forbidden("not a member of the team that owns this repo")
}

// enforceRecordedRepoWrite runs the repo-write check against the repo the
// instance was recorded against (mutations: upgrade/rollback/update/delete).
// Unknown instances defer to the service's own 404.
func (h *Handler) enforceRecordedRepoWrite(ctx context.Context, id *authn.Identity, orgID, instanceID string) error {
	if h.instances == nil {
		return nil
	}
	inst, err := h.instances.GetInstance(ctx, instanceID)
	if errors.Is(err, inventory.ErrInstanceNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if inst.OrgID != orgID {
		return nil
	}
	return h.enforceRepoWrite(ctx, id, orgID, inst.RepoID)
}

type deployInput struct {
	Org  string `path:"org"`
	Body struct {
		ItemID    string          `json:"itemId" minLength:"1"`
		ClusterID string          `json:"clusterId" minLength:"1"`
		Version   string          `json:"version,omitempty"`
		Channel   string          `json:"channel,omitempty"`
		Name      string          `json:"name,omitempty" pattern:"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" maxLength:"63" doc:"Instance name (DNS-1123 label); becomes the instance ID and repo path segment"`
		Namespace string          `json:"namespace,omitempty" pattern:"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" maxLength:"63"`
		OwnerTeam string          `json:"ownerTeam,omitempty"`
		// RepoID selects the GitOps state repo (tenant_git_repos row id);
		// empty = the org's default repo.
		RepoID string          `json:"repoId,omitempty"`
		Spec   json.RawMessage `json:"spec"`
	}
}

type deployOutput struct {
	Body struct {
		Deploy DeployResult `json:"deploy"`
	}
}

func (h *Handler) deploy(ctx context.Context, in *deployInput) (*deployOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeploymentsCreate)
	if err != nil {
		return nil, err
	}
	if err := h.enforceRepoWrite(ctx, id, org.ID, in.Body.RepoID); err != nil {
		return nil, err
	}
	res, err := h.svc.Deploy(ctx, DeployRequest{
		OrgID: org.ID, ClusterID: in.Body.ClusterID, ItemID: in.Body.ItemID,
		Version: in.Body.Version, Channel: in.Body.Channel, Name: in.Body.Name,
		Namespace: in.Body.Namespace, OwnerTeam: in.Body.OwnerTeam,
		Spec: in.Body.Spec, Requester: "user:" + id.Subject, RepoID: in.Body.RepoID,
	})
	var pve *PolicyViolationError
	if errors.As(err, &pve) {
		return nil, huma.Error422UnprocessableEntity(pve.Error())
	}
	var notInstalled *gitgithub.ErrAppNotInstalled
	if errors.As(err, &notInstalled) {
		return nil, huma.NewError(http.StatusPreconditionFailed, notInstalled.Error())
	}
	var revoked *gitgithub.ErrAppCredentialsRevoked
	if errors.As(err, &revoked) {
		return nil, huma.NewError(http.StatusBadGateway, revoked.Error())
	}
	if errors.Is(err, ErrNoGitConfig) {
		return nil, huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, ErrClusterNotActive) {
		return nil, huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, ErrInstanceExists) {
		return nil, huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, clusterregistry.ErrClusterNotFound) || errors.Is(err, ErrClusterMismatch) {
		return nil, huma.Error404NotFound("cluster not found")
	}
	if errors.Is(err, catalog.ErrItemNotFound) {
		return nil, huma.Error404NotFound("catalog item not found")
	}
	if errors.Is(err, catalog.ErrVersionNotFound) {
		return nil, huma.Error404NotFound("catalog item version not found")
	}
	if err != nil {
		return nil, err
	}
	out := &deployOutput{}
	out.Body.Deploy = *res
	return out, nil
}

type upgradeInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		ToVersion string `json:"toVersion" minLength:"1"`
		// RepoID, when set, must equal the instance's recorded repo (422
		// otherwise); empty = use the recorded repo.
		RepoID string `json:"repoId,omitempty"`
	}
}

func (h *Handler) upgrade(ctx context.Context, in *upgradeInput) (*deployOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeploymentsCreate)
	if err != nil {
		return nil, err
	}
	if err := h.enforceRecordedRepoWrite(ctx, id, org.ID, in.ID); err != nil {
		return nil, err
	}
	res, err := h.svc.Upgrade(ctx, org.ID, in.ID, in.Body.ToVersion, in.Body.RepoID, "user:"+id.Subject)
	var pve *PolicyViolationError
	if errors.As(err, &pve) {
		return nil, huma.Error422UnprocessableEntity(pve.Error())
	}
	if errors.Is(err, inventory.ErrInstanceNotFound) {
		return nil, huma.Error404NotFound("instance not found")
	}
	if errors.Is(err, ErrClusterNotActive) {
		return nil, huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, clusterregistry.ErrClusterNotFound) || errors.Is(err, ErrClusterMismatch) {
		return nil, huma.Error404NotFound("cluster not found")
	}
	if errors.Is(err, catalog.ErrVersionNotFound) {
		return nil, huma.Error404NotFound("catalog item version not found")
	}
	if err != nil {
		return nil, err
	}
	out := &deployOutput{}
	out.Body.Deploy = *res
	return out, nil
}

// instanceMutationError maps the shared instance-mutation service errors to
// HTTP statuses (update/rollback/delete share the same mapping).
func instanceMutationError(err error) error {
	var pve *PolicyViolationError
	if errors.As(err, &pve) {
		return huma.Error422UnprocessableEntity(pve.Error())
	}
	if errors.Is(err, inventory.ErrInstanceNotFound) {
		return huma.Error404NotFound("instance not found")
	}
	if errors.Is(err, ErrClusterNotActive) {
		return huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, ErrNoGitConfig) {
		return huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, ErrSameVersion) {
		return huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, ErrRepoMismatch) {
		return huma.Error422UnprocessableEntity(err.Error())
	}
	if errors.Is(err, clusterregistry.ErrClusterNotFound) || errors.Is(err, ErrClusterMismatch) {
		return huma.Error404NotFound("cluster not found")
	}
	if errors.Is(err, catalog.ErrItemNotFound) {
		return huma.Error404NotFound("catalog item not found")
	}
	if errors.Is(err, catalog.ErrVersionNotFound) {
		return huma.Error404NotFound("catalog item version not found")
	}
	return err
}

type updateInstanceInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		Spec json.RawMessage `json:"spec"`
		// RepoID, when set, must equal the instance's recorded repo (422
		// otherwise); empty = use the recorded repo.
		RepoID string `json:"repoId,omitempty"`
	}
}

func (h *Handler) updateInstance(ctx context.Context, in *updateInstanceInput) (*deployOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeploymentsCreate)
	if err != nil {
		return nil, err
	}
	if len(in.Body.Spec) == 0 {
		return nil, huma.Error422UnprocessableEntity("spec is required")
	}
	if err := h.enforceRecordedRepoWrite(ctx, id, org.ID, in.ID); err != nil {
		return nil, err
	}
	res, err := h.svc.UpdateSpec(ctx, org.ID, in.ID, in.Body.Spec, in.Body.RepoID, "user:"+id.Subject)
	if err != nil {
		return nil, instanceMutationError(err)
	}
	out := &deployOutput{}
	out.Body.Deploy = *res
	return out, nil
}

type deleteInstanceInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) deleteInstance(ctx context.Context, in *deleteInstanceInput) (*deployOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeploymentsCreate)
	if err != nil {
		return nil, err
	}
	if err := h.enforceRecordedRepoWrite(ctx, id, org.ID, in.ID); err != nil {
		return nil, err
	}
	res, err := h.svc.DeleteInstance(ctx, org.ID, in.ID, "user:"+id.Subject)
	if err != nil {
		return nil, instanceMutationError(err)
	}
	out := &deployOutput{}
	out.Body.Deploy = *res
	return out, nil
}

type rollbackInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		ToVersion string `json:"toVersion" minLength:"1"`
		// RepoID, when set, must equal the instance's recorded repo (422
		// otherwise); empty = use the recorded repo.
		RepoID string `json:"repoId,omitempty"`
	}
}

func (h *Handler) rollback(ctx context.Context, in *rollbackInput) (*deployOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationDeploymentsCreate)
	if err != nil {
		return nil, err
	}
	if err := h.enforceRecordedRepoWrite(ctx, id, org.ID, in.ID); err != nil {
		return nil, err
	}
	res, err := h.svc.Rollback(ctx, org.ID, in.ID, in.Body.ToVersion, in.Body.RepoID, "user:"+id.Subject)
	if err != nil {
		return nil, instanceMutationError(err)
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
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	d, err := h.svc.DiffPreview(ctx, org.ID, in.ID, in.ToVersion)
	if errors.Is(err, inventory.ErrInstanceNotFound) {
		return nil, huma.Error404NotFound("instance not found")
	}
	if errors.Is(err, catalog.ErrVersionNotFound) {
		return nil, huma.Error404NotFound("catalog item version not found")
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
		// ScaffoldGitOrg optionally overrides the platform scaffold git
		// org for this tenant (M8.W6); empty keeps the global default.
		ScaffoldGitOrg string `json:"scaffoldGitOrg,omitempty"`
		// GitHubApp is the optional BYO GitHub App override (model B) — a
		// credential REFERENCE only; the private key stays in ESO mounts.
		GitHubApp *types.GitHubAppConfig `json:"githubApp,omitempty"`
		// ClearGitHubApp removes a previously set BYO override, reverting
		// the tenant to the platform app (model A). Mutually exclusive
		// with githubApp; omitting both leaves any stored override intact.
		ClearGitHubApp bool `json:"clearGithubApp,omitempty"`
		// UserTemplateFallback is the policy for user-scoped scaffold
		// templates when the initiating user has no connected git identity
		// (M8.W6): "block" (default) rejects the run with a
		// connect-account deep link; "platform_app" routes the run's git
		// writes through the platform app (audited). Platform-engineer-only
		// setting; omitting it (or sending an explicit empty string)
		// preserves the stored policy. No huma enum tag: the enum validator
		// rejects the explicit-empty preserve signal with a 422 — the
		// handler validates non-empty values itself.
		UserTemplateFallback string `json:"userTemplateFallback,omitempty"`
	}
}

type gitConfigOutput struct {
	Body struct {
		Config types.TenantGitConfig    `json:"config"`
		Status *types.GitProviderStatus `json:"gitProviderStatus,omitempty"`
	}
}

// validateGitHubApp enforces the BYO app reference rules (422 on bad input).
func (h *Handler) validateGitHubApp(app *types.GitHubAppConfig) error {
	if app == nil {
		return nil
	}
	if app.AppID <= 0 || app.InstallationID <= 0 {
		return fmt.Errorf("githubApp.appId and githubApp.installationId must be positive integers")
	}
	if err := gitkeys.ValidateRef(app.KeyRef); err != nil {
		return err
	}
	if app.APIBase != "" {
		u, err := url.Parse(app.APIBase)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("githubApp.apiBase must be an absolute https:// URL")
		}
		if u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/api/v3") {
			return fmt.Errorf("githubApp.apiBase must have no query/fragment and no path other than /api/v3")
		}
		if len(h.allowedAPIBases) > 0 {
			allowed := false
			for _, base := range h.allowedAPIBases {
				// Entries may be bare hosts, host:port, or full URLs
				// (path ignored). Normalize URL forms to their host.
				b := base
				if bu, err := url.Parse(base); err == nil && bu.Host != "" {
					b = bu.Host
				}
				if strings.EqualFold(u.Host, b) || strings.EqualFold(u.Hostname(), b) {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("githubApp.apiBase host %q is not in the platform allowlist", u.Host)
			}
		}
	}
	return nil
}

func (h *Handler) setGitConfig(ctx context.Context, in *gitConfigInput) (*struct{}, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantSettingsWrite)
	if err != nil {
		return nil, err
	}
	if in.Body.ClearGitHubApp && in.Body.GitHubApp != nil {
		return nil, huma.Error422UnprocessableEntity("clearGithubApp and githubApp are mutually exclusive")
	}
	if err := h.validateGitHubApp(in.Body.GitHubApp); err != nil {
		return nil, huma.Error422UnprocessableEntity(err.Error())
	}
	if fb := in.Body.UserTemplateFallback; fb != "" && fb != "block" && fb != "platform_app" {
		return nil, huma.Error422UnprocessableEntity(`userTemplateFallback must be "block" or "platform_app"`)
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
		ScaffoldGitOrg: in.Body.ScaffoldGitOrg, GitHubApp: in.Body.GitHubApp,
		ClearGitHubApp: in.Body.ClearGitHubApp, UserTemplateFallback: in.Body.UserTemplateFallback,
	})
}

type gitConfigGetInput struct {
	Org string `path:"org"`
}

func (h *Handler) getGitConfig(ctx context.Context, in *gitConfigGetInput) (*gitConfigOutput, error) {
	org, _, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
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
	// Best-effort health probe; failures degrade to "unknown", never 5xx.
	if st, err := h.svc.GitProviderStatus(ctx, org.ID); err == nil {
		out.Body.Status = st
	}
	return out, nil
}
