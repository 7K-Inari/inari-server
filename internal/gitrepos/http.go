// HTTP handlers for the gitrepos module (Feature A, plan §4): the
// team-filtered repo registry REST surface. Conventions mirror
// internal/orchestrator/http.go (huma operations, authorizeOrg, typed
// error → status mapping).
package gitrepos

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	gitgithub "github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider/github"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TenantTeamResolver resolves tenant slugs and enumerates org teams (the
// tenancy.Service seam the handler needs for team filtering).
type TenantTeamResolver interface {
	GetTenant(ctx context.Context, slug string) (*types.Organization, error)
	ListTeams(ctx context.Context, orgID string) ([]types.Team, error)
}

// Handler exposes the repo-registry REST surface.
type Handler struct {
	svc     *Service
	tenants TenantTeamResolver
	authz   authz.Authorizer
}

func NewHandler(svc *Service, tenants TenantTeamResolver, az authz.Authorizer) *Handler {
	return &Handler{svc: svc, tenants: tenants, authz: az}
}

// RegisterRoutes mounts the repo-registry API on the huma API instance.
func (h *Handler) RegisterRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "listGitRepos",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/git-repos",
		Summary:     "List the org's registered GitOps repos (team-filtered)",
		Security:    httpserver.SecurityRequirement(),
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID: "registerGitRepo",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/git-repos",
		Summary:     "Register an existing git repo (validates the GitHub App is installed)",
		Security:    httpserver.SecurityRequirement(),
	}, h.register)

	huma.Register(api, huma.Operation{
		OperationID: "getGitRepo",
		Method:      http.MethodGet,
		Path:        "/api/v1/tenants/{org}/git-repos/{id}",
		Summary:     "Repo detail + provider health probe",
		Security:    httpserver.SecurityRequirement(),
	}, h.get)

	huma.Register(api, huma.Operation{
		OperationID: "updateGitRepo",
		Method:      http.MethodPatch,
		Path:        "/api/v1/tenants/{org}/git-repos/{id}",
		Summary:     "Update repo policy/branch/team or promote to the org default",
		Security:    httpserver.SecurityRequirement(),
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID: "unregisterGitRepo",
		Method:      http.MethodDelete,
		Path:        "/api/v1/tenants/{org}/git-repos/{id}",
		Summary:     "Unregister a repo (guarded; force with mode=orphan|teardown)",
		Security:    httpserver.SecurityRequirement(),
	}, h.unregister)

	huma.Register(api, huma.Operation{
		OperationID: "ensureGitRepoWebhook",
		Method:      http.MethodPost,
		Path:        "/api/v1/tenants/{org}/git-repos/{id}/webhook",
		Summary:     "(Re)provision the repo's webhook (rotates the secret)",
		Security:    httpserver.SecurityRequirement(),
	}, h.ensureWebhook)
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

// callerTeams resolves the caller's team IDs inside the org via the shared
// group-claim matcher (decision 5; the identity-side convention, no FGA
// round-trip).
func (h *Handler) callerTeams(ctx context.Context, id *authn.Identity, orgID string) ([]string, error) {
	teams, err := h.tenants.ListTeams(ctx, orgID)
	if err != nil {
		return nil, err
	}
	return authn.CallerTeamIDs(id, teams), nil
}

// hasRelation is a fail-closed relation check used for the privilege
// escalation paths (settings-write bypass, deployments_create team writes).
func (h *Handler) hasRelation(ctx context.Context, subject, relation, orgID string) bool {
	ok, err := h.authz.Check(ctx, authz.UserObject(subject), relation, authz.OrgObject(orgID))
	return err == nil && ok
}

// listFilterForCaller returns nil (see all) for privileged callers
// (tenant_settings_write: org admins / platform team), otherwise the
// caller's team IDs (baseline read-all + own teams, decision 5).
func (h *Handler) listFilterForCaller(ctx context.Context, id *authn.Identity, orgID string) ([]string, error) {
	if h.hasRelation(ctx, id.Subject, authz.RelationTenantSettingsWrite, orgID) {
		return nil, nil
	}
	return h.callerTeams(ctx, id, orgID)
}

// canSeeRepo enforces per-repo read visibility: platform repos are
// read-visible to every org member; team repos to owning-team members;
// privileged callers see all.
func (h *Handler) canSeeRepo(r *types.TenantGitRepo, callerTeams []string, privileged bool) bool {
	if privileged || r.Scope == types.GitRepoScopePlatform {
		return true
	}
	for _, t := range callerTeams {
		if t == r.TeamID {
			return true
		}
	}
	return false
}

// canWriteRepo enforces per-repo write authorization: platform repos
// require tenant_settings_write; team repos allow owning-team members with
// deployments_create (decision 5b) in addition to settings-write.
func (h *Handler) canWriteRepo(r *types.TenantGitRepo, callerTeams []string, settingsWrite, deploymentsCreate bool) bool {
	if settingsWrite {
		return true
	}
	if r.Scope == types.GitRepoScopeTeam && deploymentsCreate {
		for _, t := range callerTeams {
			if t == r.TeamID {
				return true
			}
		}
	}
	return false
}

// repoError maps service errors to HTTP statuses (mirrors the orchestrator
// mapping: 412 app-not-installed, 502 credentials-revoked).
func repoError(err error) error {
	var notInstalled *gitgithub.ErrAppNotInstalled
	if errors.As(err, &notInstalled) {
		return huma.NewError(http.StatusPreconditionFailed, notInstalled.Error())
	}
	var revoked *gitgithub.ErrAppCredentialsRevoked
	if errors.As(err, &revoked) {
		return huma.NewError(http.StatusBadGateway, revoked.Error())
	}
	var inUse *RepoInUseError
	if errors.As(err, &inUse) {
		return huma.NewError(http.StatusConflict, inUse.Error())
	}
	if errors.Is(err, inventory.ErrRepoNotFound) {
		return huma.Error404NotFound("git repo not found")
	}
	if errors.Is(err, ErrRepoConflict) {
		return huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, inventory.ErrTeamNotInOrg) {
		return huma.Error422UnprocessableEntity(err.Error())
	}
	if errors.Is(err, ErrWebhookDisabled) {
		return huma.Error501NotImplemented(err.Error())
	}
	if errors.Is(err, ErrInvalidInput) {
		return huma.Error422UnprocessableEntity(err.Error())
	}
	return err
}

type listInput struct {
	Org string `path:"org"`
}

type listOutput struct {
	Body struct {
		Repos []*types.TenantGitRepo `json:"repos"`
	}
}

func (h *Handler) list(ctx context.Context, in *listInput) (*listOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	filter, err := h.listFilterForCaller(ctx, id, org.ID)
	if err != nil {
		return nil, err
	}
	repos, err := h.svc.List(ctx, org.ID, filter)
	if err != nil {
		return nil, err
	}
	out := &listOutput{}
	out.Body.Repos = repos
	if out.Body.Repos == nil {
		out.Body.Repos = []*types.TenantGitRepo{}
	}
	return out, nil
}

type registerInput struct {
	Org  string `path:"org"`
	Body struct {
		Name         string `json:"name" minLength:"1" maxLength:"63"`
		Repo         string `json:"repo" minLength:"3" doc:"owner/name of the existing repo"`
		Provider     string `json:"provider,omitempty" enum:"github" doc:"only github is active in this phase"`
		Scope        string `json:"scope,omitempty" enum:"platform,team"`
		TeamID       string `json:"teamId,omitempty" doc:"owning team (team scope only)"`
		CommitPolicy string `json:"commitPolicy,omitempty" enum:"direct,pull_request"`
		BaseBranch   string `json:"baseBranch,omitempty"`
		IsDefault    bool   `json:"isDefault,omitempty"`
	}
}

type repoOutput struct {
	Body struct {
		Repo   *types.TenantGitRepo     `json:"repo"`
		Status *types.GitProviderStatus `json:"gitProviderStatus,omitempty"`
		// WebhookStatus surfaces the M4 webhook registration state on
		// repo detail/register/update responses.
		WebhookStatus string `json:"webhookStatus" enum:"provisioned,unprovisioned,disabled" doc:"webhook registration state: provisioned (provider hook live), unprovisioned (reconcile sweeper retries; repair via POST .../git-repos/{id}/webhook), disabled (provisioning not configured)"`
	}
}

func (h *Handler) register(ctx context.Context, in *registerInput) (*repoOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantSettingsWrite)
	if err != nil {
		return nil, err
	}
	row, err := h.svc.Register(ctx, org.ID, RegisterInput{
		Name: in.Body.Name, Repo: in.Body.Repo, Provider: in.Body.Provider,
		Scope: types.GitRepoScope(in.Body.Scope), TeamID: in.Body.TeamID,
		CommitPolicy: types.CommitPolicy(in.Body.CommitPolicy), BaseBranch: in.Body.BaseBranch,
		IsDefault: in.Body.IsDefault,
	}, "user:"+id.Subject)
	if err != nil {
		return nil, repoError(err)
	}
	out := &repoOutput{}
	out.Body.Repo = row
	out.Body.WebhookStatus = h.svc.WebhookProvisioningStatus(row)
	return out, nil
}

type getInput struct {
	Org string `path:"org"`
	ID  string `path:"id"`
}

func (h *Handler) get(ctx context.Context, in *getInput) (*repoOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	row, err := h.svc.Get(ctx, org.ID, in.ID)
	if err != nil {
		return nil, repoError(err)
	}
	privileged := h.hasRelation(ctx, id.Subject, authz.RelationTenantSettingsWrite, org.ID)
	teams, err := h.callerTeams(ctx, id, org.ID)
	if err != nil {
		return nil, err
	}
	if !h.canSeeRepo(row, teams, privileged) {
		return nil, huma.Error404NotFound("git repo not found")
	}
	out := &repoOutput{}
	out.Body.Repo = row
	// Best-effort health probe; failures degrade to "unknown", never 5xx.
	out.Body.Status = h.svc.Probe(ctx, row)
	out.Body.WebhookStatus = h.svc.WebhookProvisioningStatus(row)
	return out, nil
}

type updateInput struct {
	Org  string `path:"org"`
	ID   string `path:"id"`
	Body struct {
		Name         *string `json:"name,omitempty"`
		CommitPolicy *string `json:"commitPolicy,omitempty" enum:"direct,pull_request"`
		BaseBranch   *string `json:"baseBranch,omitempty"`
		TeamID       *string `json:"teamId,omitempty"`
		IsDefault    *bool   `json:"isDefault,omitempty" doc:"true promotes (demoting the old default); false is rejected"`
	}
}

func (h *Handler) update(ctx context.Context, in *updateInput) (*repoOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantRead)
	if err != nil {
		return nil, err
	}
	row, err := h.svc.Get(ctx, org.ID, in.ID)
	if err != nil {
		return nil, repoError(err)
	}
	teams, err := h.callerTeams(ctx, id, org.ID)
	if err != nil {
		return nil, err
	}
	settingsWrite := h.hasRelation(ctx, id.Subject, authz.RelationTenantSettingsWrite, org.ID)
	deploymentsCreate := h.hasRelation(ctx, id.Subject, authz.RelationDeploymentsCreate, org.ID)
	// Default promotion, team reassignment, and platform-repo writes are
	// settings-write only; owning-team deployers may patch policy/branch.
	needsSettings := (in.Body.IsDefault != nil) || (in.Body.TeamID != nil) || row.Scope == types.GitRepoScopePlatform
	if needsSettings && !settingsWrite {
		return nil, huma.Error403Forbidden("insufficient permissions")
	}
	if !needsSettings && !h.canWriteRepo(row, teams, settingsWrite, deploymentsCreate) {
		return nil, huma.Error403Forbidden("insufficient permissions")
	}
	updated, err := h.svc.Update(ctx, org.ID, in.ID, PatchInput{
		Name: in.Body.Name, CommitPolicy: in.Body.CommitPolicy,
		BaseBranch: in.Body.BaseBranch, TeamID: in.Body.TeamID, IsDefault: in.Body.IsDefault,
	}, "user:"+id.Subject)
	if err != nil {
		return nil, repoError(err)
	}
	out := &repoOutput{}
	out.Body.Repo = updated
	out.Body.WebhookStatus = h.svc.WebhookProvisioningStatus(updated)
	return out, nil
}

type unregisterInput struct {
	Org   string `path:"org"`
	ID    string `path:"id"`
	Force bool   `query:"force"`
	Mode  string `query:"mode" enum:"orphan,teardown" doc:"required with force=true"`
}

type unregisterOutput struct {
	Body struct {
		Unregistered bool   `json:"unregistered"`
		Mode         string `json:"mode,omitempty"`
	}
}

func (h *Handler) unregister(ctx context.Context, in *unregisterInput) (*unregisterOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantSettingsWrite)
	if err != nil {
		return nil, err
	}
	if err := h.svc.Unregister(ctx, org.ID, in.ID, in.Force, UnregisterMode(in.Mode), "user:"+id.Subject); err != nil {
		return nil, repoError(err)
	}
	out := &unregisterOutput{}
	out.Body.Unregistered = true
	out.Body.Mode = in.Mode
	return out, nil
}

type webhookOutput struct {
	Body struct {
		Provisioned bool   `json:"provisioned"`
		HookURL     string `json:"hookUrl,omitempty"`
	}
}

func (h *Handler) ensureWebhook(ctx context.Context, in *getInput) (*webhookOutput, error) {
	org, id, err := h.authorizeOrg(ctx, in.Org, authz.RelationTenantSettingsWrite)
	if err != nil {
		return nil, err
	}
	st, err := h.svc.EnsureWebhook(ctx, org.ID, in.ID, "user:"+id.Subject)
	if err != nil {
		return nil, repoError(err)
	}
	out := &webhookOutput{}
	out.Body.Provisioned = st.Provisioned
	out.Body.HookURL = st.HookURL
	return out, nil
}
