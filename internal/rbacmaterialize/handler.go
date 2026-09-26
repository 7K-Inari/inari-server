package rbacmaterialize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Tenancy is the tenancy seam the handler needs (satisfied by
// tenancy.Service).
type Tenancy interface {
	GetTenantByID(ctx context.Context, id string) (*types.Organization, error)
	ListTeams(ctx context.Context, orgID string) ([]types.Team, error)
}

// GitConfigs resolves the tenant's git target (satisfied by an adapter
// over inventory.Store). A nil config means no git-config row: the
// materializer falls back to the platform-owned <slug>-inari-state repo.
type GitConfigs interface {
	GitConfig(ctx context.Context, orgID string) (*types.TenantGitConfig, error)
}

// Handler implements audit.Handler for RBAC-relevant lifecycle events
// (plan §7.1): every event triggers a full desired-state re-render and
// commit of the tenant's anchor ClusterRoles + group bindings into the
// tenant state repo, so role changes, team adds and team removes all
// converge. The render is deterministic, so redelivery after a partial
// failure produces either a no-op commit or the same content — safe under
// the dispatcher's at-least-once delivery.
type Handler struct {
	tenancy Tenancy
	configs GitConfigs
	git     gitprovider.Provider
	log     *slog.Logger
	// stateRepoOrg prefixes the fallback <slug>-inari-state repo with the
	// platform git owner (e.g. "7k-group") for providers that require
	// owner-qualified repo names (github). Empty keeps the bare
	// convention (fake/local providers).
	stateRepoOrg string
}

// NewHandler wires the outbox consumer; a nil logger uses slog.Default.
func NewHandler(ten Tenancy, configs GitConfigs, git gitprovider.Provider, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{tenancy: ten, configs: configs, git: git, log: log}
}

// WithStateRepoOrg sets the git owner for the fallback tenant state repo
// (INARI_GIT_STATE_REPO_ORG).
func (h *Handler) WithStateRepoOrg(org string) *Handler {
	h.stateRepoOrg = org
	return h
}

// EventTypes implements audit.Handler.
func (h *Handler) EventTypes() []string {
	return []string{
		types.EventRBACMappingsUpdated,
		types.EventTenantCreated,
		types.EventTeamCreated,
		types.EventTeamDeleted,
	}
}

// Handle re-renders and commits the tenant RBAC bundle. Unknown orgs
// (already deleted) are skipped without error — retrying would never
// succeed. Git and store errors propagate so the dispatcher retries.
func (h *Handler) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	var p struct {
		OrgID string `json:"orgId"`
	}
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return fmt.Errorf("rbacmaterialize: payload: %w", err)
	}
	if p.OrgID == "" {
		return fmt.Errorf("rbacmaterialize: event %s carries no orgId", ev.EventType)
	}
	org, err := h.tenancy.GetTenantByID(ctx, p.OrgID)
	if errors.Is(err, tenancy.ErrOrgNotFound) {
		h.log.Info("rbacmaterialize: skipped, org gone", "org", p.OrgID, "event", ev.EventType)
		return nil
	}
	if err != nil {
		return fmt.Errorf("rbacmaterialize: load org: %w", err)
	}
	teams, err := h.tenancy.ListTeams(ctx, org.ID)
	if err != nil {
		return fmt.Errorf("rbacmaterialize: list teams: %w", err)
	}
	repo, branch, policy := h.target(ctx, org)
	files := RenderTenantRBAC(org.Slug, teams)
	cloneURL, err := h.git.EnsureRepo(ctx, repo)
	if err != nil {
		return fmt.Errorf("rbacmaterialize: ensure repo %s: %w", repo, err)
	}
	// Repos created outside the tenant zone flow have no ArgoCD root app;
	// seed it once so the tenant-local ArgoCD actually syncs baseline/.
	// An existing root app (TZF-managed) is never overwritten.
	if root, err := h.git.ReadFile(ctx, repo, branch, RootAppPath); err != nil {
		return fmt.Errorf("rbacmaterialize: read root app: %w", err)
	} else if root == "" {
		files = append(files, RenderRootApp(cloneURL))
	}
	message := "chore(rbac): tenant " + org.Slug + " cluster roles and group bindings"
	if policy == types.CommitPolicyPullRequest {
		if _, err := h.git.OpenPR(ctx, repo, branch, message, "", files); err != nil {
			return fmt.Errorf("rbacmaterialize: open PR on %s: %w", repo, err)
		}
		return nil
	}
	if _, err := h.git.CommitFiles(ctx, repo, branch, files, message); err != nil {
		return fmt.Errorf("rbacmaterialize: commit to %s: %w", repo, err)
	}
	return nil
}

// target resolves repo/branch/policy from the tenant git-config, falling
// back to the platform convention (<slug>-inari-state, main, direct;
// owner-qualified with stateRepoOrg when configured).
func (h *Handler) target(ctx context.Context, org *types.Organization) (repo, branch string, policy types.CommitPolicy) {
	repo, branch, policy = org.Slug+"-inari-state", "main", types.CommitPolicyDirect
	if h.stateRepoOrg != "" {
		repo = h.stateRepoOrg + "/" + repo
	}
	cfg, err := h.configs.GitConfig(ctx, org.ID)
	if err != nil {
		// A broken config lookup must not block materialization for every
		// tenant; fall back to the convention and let the commit itself
		// surface any real git problem.
		h.log.Warn("rbacmaterialize: git config lookup failed, using defaults", "org", org.ID, "error", err)
		return repo, branch, policy
	}
	if cfg == nil {
		return repo, branch, policy
	}
	if cfg.Repo != "" {
		repo = cfg.Repo
	}
	if cfg.BaseBranch != "" {
		branch = cfg.BaseBranch
	}
	if cfg.CommitPolicy != "" {
		policy = cfg.CommitPolicy
	}
	return repo, branch, policy
}
