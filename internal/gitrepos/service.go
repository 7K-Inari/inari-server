// Package gitrepos is the multi-repo GitOps registry (Feature A, plan §4):
// an org's platform baselines plus team-scoped state repos, replacing the
// single-repo-per-org model. The service owns registration (with fail-fast
// GitHub App installation validation, decision 3c), team-filtered listing
// (decision 5), policy/default updates (baseline replacement flow), and
// guarded unregistration with orphan/teardown modes (decision 6).
package gitrepos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/impersonation"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrInvalidInput is a 422-class validation failure (bad provider, scope/
// team incoherence, malformed repo slug, explicit default demotion).
var ErrInvalidInput = errors.New("gitrepos: invalid input")

// ErrRepoConflict is a 409-class failure: the repo slug is already
// registered under a different name in this org.
var ErrRepoConflict = errors.New("gitrepos: repo already registered")

// UnregisterMode selects the forced-delete semantics (decision 6).
type UnregisterMode string

const (
	// UnregisterModeOrphan unregisters only; workloads keep running and
	// Inari stops managing them (FK ON DELETE SET NULL orphans references).
	UnregisterModeOrphan UnregisterMode = "orphan"
	// UnregisterModeTeardown additionally deletes the addon/instance
	// manifests from the repo and enqueues ArgoCD app deletions via the
	// agent (destructive, audit-logged).
	UnregisterModeTeardown UnregisterMode = "teardown"
)

// RepoInUseError carries the affected-workload counts for the 409 response
// when an unregister is blocked (also the UI confirmation content).
type RepoInUseError struct {
	RepoID string
	Refs   *types.GitRepoRefCounts
	// Default reports that the block is the org-default rule (promote
	// another platform repo first), not live references.
	Default bool
}

// Unwrap lets errors.Is(err, inventory.ErrRepoInUse) match, keeping the
// store's sentinel as the canonical in-use signal.
func (e *RepoInUseError) Unwrap() error { return inventory.ErrRepoInUse }

func (e *RepoInUseError) Error() string {
	if e.Default {
		return "gitrepos: repo is the org default; promote another platform repo first"
	}
	return fmt.Sprintf("gitrepos: repo in use (instances=%d addons=%d clusters=%d)",
		e.Refs.Instances, e.Refs.Addons, e.Refs.Clusters)
}

// Store is the inventory seam the service needs.
type Store interface {
	ListGitRepos(ctx context.Context, q db.Querier, orgID string, teamIDs []string) ([]*types.TenantGitRepo, error)
	GetGitRepo(ctx context.Context, q db.Querier, orgID, id string) (*types.TenantGitRepo, error)
	GetDefaultGitRepo(ctx context.Context, q db.Querier, orgID string) (*types.TenantGitRepo, error)
	UpsertGitRepo(ctx context.Context, q db.Querier, r *types.TenantGitRepo) error
	DeleteGitRepo(ctx context.Context, q db.Querier, orgID, id string) error
	SetDefaultGitRepo(ctx context.Context, q db.Querier, orgID, id string) error
	GitRepoRefCounts(ctx context.Context, q db.Querier, orgID, repoID string) (*types.GitRepoRefCounts, error)
	ListGitRepoInstances(ctx context.Context, q db.Querier, orgID, repoID string) ([]inventory.GitRepoInstanceRef, error)
	ListGitRepoAddons(ctx context.Context, q db.Querier, orgID, repoID string) ([]inventory.GitRepoAddonRef, error)
}

// Queue is the agent command queue seam (agentgateway.Queue).
type Queue interface {
	Enqueue(ctx context.Context, cmd *types.AgentCommand) error
}

// RegisterInput is one repo-registration request.
type RegisterInput struct {
	Name         string
	Repo         string // owner/name
	Provider     string // only "github" active (decision 7)
	Scope        types.GitRepoScope
	TeamID       string
	CommitPolicy types.CommitPolicy
	BaseBranch   string
	IsDefault    bool
	GitHubApp    *types.GitHubAppConfig
}

// PatchInput is a partial repo update. Nil fields are left untouched.
type PatchInput struct {
	Name           *string
	CommitPolicy   *string
	BaseBranch     *string
	TeamID         *string // team-scope repos only
	IsDefault      *bool   // true promotes (demoting the old default); false is rejected
	GitHubApp      *types.GitHubAppConfig
	ClearGitHubApp bool
}

// Service is the repo-registry module.
type Service struct {
	db    *db.DB
	store Store
	git   gitprovider.Resolver
	queue Queue
	audit *audit.Store
}

// NewService wires the module. db may be nil in unit tests (audit/outbox
// TXs are then skipped); queue may be nil (teardown then skips agent
// commands); audit may be nil (audit writes skipped).
func NewService(store Store, git gitprovider.Resolver, queue Queue, auditStore *audit.Store, dbs ...*db.DB) *Service {
	s := &Service{store: store, git: git, queue: queue, audit: auditStore}
	if len(dbs) > 0 {
		s.db = dbs[0]
	}
	return s
}

var repoSlugPattern = func(repo string) bool {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.ContainsAny(p, " \t\n") {
			return false
		}
	}
	return true
}

// List returns the org's repos, filtered to platform repos plus the given
// teams' repos when teamIDs is non-empty (decision 5).
func (s *Service) List(ctx context.Context, orgID string, teamIDs []string) ([]*types.TenantGitRepo, error) {
	return s.store.ListGitRepos(ctx, s.querier(), orgID, teamIDs)
}

// Get returns one repo, scoped to the org.
func (s *Service) Get(ctx context.Context, orgID, id string) (*types.TenantGitRepo, error) {
	return s.store.GetGitRepo(ctx, s.querier(), orgID, id)
}

// Probe health-checks the repo's git provider auth, reusing the resolver's
// Probe seam (orchestrator GitProviderStatus pattern); a resolver without
// Probe degrades to "unknown".
func (s *Service) Probe(ctx context.Context, r *types.TenantGitRepo) *types.GitProviderStatus {
	prober, ok := s.git.(interface {
		Probe(context.Context, *types.TenantGitConfig) *types.GitProviderStatus
	})
	if !ok {
		return &types.GitProviderStatus{State: "unknown", AuthModel: "static"}
	}
	return prober.Probe(ctx, cfgFromRepo(r))
}

// Register validates input, fail-fast checks the GitHub App is installed in
// the target git org (decision 3c), persists the row, and audits.
func (s *Service) Register(ctx context.Context, orgID string, in RegisterInput, actor string) (*types.TenantGitRepo, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if !repoSlugPattern(in.Repo) {
		return nil, fmt.Errorf("%w: repo must be owner/name", ErrInvalidInput)
	}
	provider := in.Provider
	if provider == "" {
		provider = string(types.GitRepoProviderGitHub)
	}
	if provider != string(types.GitRepoProviderGitHub) {
		return nil, fmt.Errorf("%w: provider %q not supported (only github is active)", ErrInvalidInput, in.Provider)
	}
	scope := in.Scope
	if scope == "" {
		scope = types.GitRepoScopeTeam
	}
	switch scope {
	case types.GitRepoScopeTeam:
		if in.TeamID == "" {
			return nil, fmt.Errorf("%w: team-scope repos require teamId", ErrInvalidInput)
		}
	case types.GitRepoScopePlatform:
		if in.TeamID != "" {
			return nil, fmt.Errorf("%w: platform repos cannot have a team", ErrInvalidInput)
		}
	default:
		return nil, fmt.Errorf("%w: scope must be platform or team", ErrInvalidInput)
	}
	if in.TeamID != "" {
		if _, err := uuid.Parse(in.TeamID); err != nil {
			return nil, fmt.Errorf("%w: teamId must be a UUID", ErrInvalidInput)
		}
	}

	row := &types.TenantGitRepo{
		OrgID: orgID, Name: in.Name, Repo: in.Repo,
		Provider: types.GitRepoProvider(provider), Scope: scope, TeamID: in.TeamID,
		CommitPolicy: in.CommitPolicy, BaseBranch: in.BaseBranch,
		IsDefault: in.IsDefault, GitHubApp: in.GitHubApp,
	}
	if row.CommitPolicy == "" {
		row.CommitPolicy = types.CommitPolicyDirect
	}
	if row.BaseBranch == "" {
		row.BaseBranch = "main"
	}

	// Registering straight into the default slot when the org already has a
	// default would fail deep in the upsert on one_default_repo_per_org and
	// surface as a misleading "repo already registered" 409 — pre-check and
	// point the caller at the PATCH-promote flow instead.
	if row.IsDefault {
		existing, err := s.store.GetDefaultGitRepo(ctx, s.querier(), orgID)
		if err != nil && !errors.Is(err, inventory.ErrRepoNotFound) {
			return nil, err
		}
		if existing != nil {
			return nil, fmt.Errorf("%w: org already has a default repo (%s); register without isDefault and promote via PATCH instead",
				ErrInvalidInput, existing.Name)
		}
	}

	// Fail fast: the app must be installed in the repo's git org before we
	// register (decision 3c). Resolution itself performs installation
	// discovery; ErrAppNotInstalled/ErrAppCredentialsRevoked propagate typed.
	if _, _, err := s.git.ForTenant(ctx, cfgFromRepo(row)); err != nil {
		return nil, err
	}

	write := func(q db.Querier) error {
		if err := s.store.UpsertGitRepo(ctx, q, row); err != nil {
			if isUniqueViolation(err) {
				return ErrRepoConflict
			}
			return err
		}
		return s.recordAudit(ctx, q, orgID, actor, "gitrepo.registered", row.ID, map[string]any{
			"name": row.Name, "repo": row.Repo, "scope": string(row.Scope), "teamId": row.TeamID,
		})
	}
	if err := s.inTx(ctx, write); err != nil {
		if errors.Is(err, ErrRepoConflict) || errors.Is(err, inventory.ErrTeamNotInOrg) {
			return nil, err
		}
		if isUniqueViolation(err) {
			return nil, ErrRepoConflict
		}
		return nil, err
	}
	return row, nil
}

// Update applies a partial update; IsDefault=true promotes the repo and
// demotes the previous default atomically (baseline replacement flow).
func (s *Service) Update(ctx context.Context, orgID, id string, in PatchInput, actor string) (*types.TenantGitRepo, error) {
	row, err := s.store.GetGitRepo(ctx, s.querier(), orgID, id)
	if err != nil {
		return nil, err
	}
	if in.IsDefault != nil && !*in.IsDefault {
		return nil, fmt.Errorf("%w: cannot demote the default directly; promote another repo instead", ErrInvalidInput)
	}
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
		}
		row.Name = *in.Name
	}
	if in.CommitPolicy != nil {
		cp := types.CommitPolicy(*in.CommitPolicy)
		if cp != types.CommitPolicyDirect && cp != types.CommitPolicyPullRequest {
			return nil, fmt.Errorf("%w: commitPolicy must be direct or pull_request", ErrInvalidInput)
		}
		row.CommitPolicy = cp
	}
	if in.BaseBranch != nil {
		if strings.TrimSpace(*in.BaseBranch) == "" {
			return nil, fmt.Errorf("%w: baseBranch must not be empty", ErrInvalidInput)
		}
		row.BaseBranch = *in.BaseBranch
	}
	if in.TeamID != nil {
		if row.Scope != types.GitRepoScopeTeam && *in.TeamID != "" {
			return nil, fmt.Errorf("%w: platform repos cannot have a team", ErrInvalidInput)
		}
		if *in.TeamID != "" {
			if _, err := uuid.Parse(*in.TeamID); err != nil {
				return nil, fmt.Errorf("%w: teamId must be a UUID", ErrInvalidInput)
			}
		}
		row.TeamID = *in.TeamID
	}
	if in.GitHubApp != nil {
		row.GitHubApp = in.GitHubApp
	}
	row.ClearGitHubApp = in.ClearGitHubApp

	err = s.inTx(ctx, func(q db.Querier) error {
		if err := s.store.UpsertGitRepo(ctx, q, row); err != nil {
			if isUniqueViolation(err) {
				return ErrRepoConflict
			}
			return err
		}
		if in.IsDefault != nil && *in.IsDefault {
			if err := s.store.SetDefaultGitRepo(ctx, q, orgID, id); err != nil {
				return err
			}
			row.IsDefault = true
		}
		return s.recordAudit(ctx, q, orgID, actor, "gitrepo.updated", id, map[string]any{
			"name": row.Name, "repo": row.Repo, "promotedDefault": in.IsDefault != nil && *in.IsDefault,
		})
	})
	if err != nil {
		return nil, err
	}
	// Re-read so the response reflects the persisted row (default flag,
	// BYO preserve semantics).
	return s.store.GetGitRepo(ctx, s.querier(), orgID, id)
}

// Unregister removes a repo row, guarded by live references (decision 6).
// Without force, any reference (or the default flag) blocks with a
// RepoInUseError carrying the affected-workload counts. Forced orphan
// deletes the row only; forced teardown additionally deletes the workload
// manifests from the repo and enqueues ArgoCD app deletions before the row
// delete, so a crash mid-flow leaves a recoverable state.
func (s *Service) Unregister(ctx context.Context, orgID, id string, force bool, mode UnregisterMode, actor string) error {
	row, err := s.store.GetGitRepo(ctx, s.querier(), orgID, id)
	if err != nil {
		return err
	}
	if row.IsDefault {
		return &RepoInUseError{RepoID: id, Default: true, Refs: &types.GitRepoRefCounts{}}
	}
	refs, err := s.store.GitRepoRefCounts(ctx, s.querier(), orgID, id)
	if err != nil {
		return err
	}
	if !force {
		if refs.Total() > 0 {
			return &RepoInUseError{RepoID: id, Refs: refs}
		}
		return s.deleteRow(ctx, orgID, id, actor, string(UnregisterModeOrphan), refs)
	}
	switch mode {
	case UnregisterModeOrphan:
		return s.deleteRow(ctx, orgID, id, actor, string(mode), refs)
	case UnregisterModeTeardown:
		return s.teardown(ctx, orgID, row, refs, actor)
	default:
		return fmt.Errorf("%w: mode must be orphan or teardown when force=true", ErrInvalidInput)
	}
}

// teardown deletes workload manifests from the repo, enqueues ArgoCD app
// deletions, then deletes the row (destructive, audit-logged, decision 6).
func (s *Service) teardown(ctx context.Context, orgID string, row *types.TenantGitRepo, refs *types.GitRepoRefCounts, actor string) error {
	instances, err := s.store.ListGitRepoInstances(ctx, s.querier(), orgID, row.ID)
	if err != nil {
		return err
	}
	addons, err := s.store.ListGitRepoAddons(ctx, s.querier(), orgID, row.ID)
	if err != nil {
		return err
	}

	git, _, err := s.git.ForTenant(ctx, cfgFromRepo(row))
	if err != nil {
		return err
	}
	var paths []string
	for _, inst := range instances {
		p := orchestrator.RepoPath(inst.ClusterID, inst.CatalogItemID, inst.ID)
		paths = append(paths, p+"/instance.yaml", p+"/application.yaml")
	}
	for _, a := range addons {
		if a.RepoPath != "" {
			paths = append(paths, a.RepoPath+"/application.yaml", a.RepoPath+"/applicationset.yaml", a.RepoPath+"/values.yaml")
		}
	}
	if len(paths) > 0 {
		message := fmt.Sprintf("unregister repo %s: teardown %d instance/addon manifest paths", row.Repo, len(paths))
		if _, err := git.DeleteFiles(ctx, row.Repo, row.BaseBranch, paths, message); err != nil {
			return fmt.Errorf("gitrepos: teardown manifest delete: %w", err)
		}
	}
	// Best-effort agent cleanup per workload (mirrors orchestrator's
	// undeploy: git delete already stops reconciliation).
	for _, inst := range instances {
		_ = s.enqueueAppDeletion(ctx, inst.ClusterID, "inari-"+inst.ID)
	}
	for _, a := range addons {
		if a.ArgoCDApp != "" && a.ClusterID != "*" {
			_ = s.enqueueAppDeletion(ctx, a.ClusterID, a.ArgoCDApp)
		}
	}
	return s.deleteRow(ctx, orgID, row.ID, actor, string(UnregisterModeTeardown), refs)
}

// deleteRow removes the row with audit in one TX.
func (s *Service) deleteRow(ctx context.Context, orgID, id, actor, mode string, refs *types.GitRepoRefCounts) error {
	return s.inTx(ctx, func(q db.Querier) error {
		if err := s.store.DeleteGitRepo(ctx, q, orgID, id); err != nil {
			return err
		}
		return s.recordAudit(ctx, q, orgID, actor, "gitrepo.unregistered", id, map[string]any{
			"mode": mode, "refs": refs,
		})
	})
}

// enqueueAppDeletion dispatches an InvokeAction (delete) for one ArgoCD
// Application to the cluster's agent (same command shape as the
// orchestrator's undeploy path).
func (s *Service) enqueueAppDeletion(ctx context.Context, clusterID, appName string) error {
	if s.queue == nil {
		return nil
	}
	cmd := &agentv1.InvokeAction{
		CommandId: appName,
		Action:    "delete",
		Resource: &agentv1.ResourceRef{
			Kind:      "Application",
			Name:      appName,
			Namespace: "argocd",
		},
	}
	any, err := anypb.New(cmd)
	if err != nil {
		return err
	}
	raw, err := protojson.Marshal(any)
	if err != nil {
		return err
	}
	return s.queue.Enqueue(ctx, &types.AgentCommand{
		ID:        "delete-argocd-app:" + appName,
		ClusterID: clusterID,
		Type:      agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_INVOKE_ACTION),
		Payload:   raw,
	})
}

// cfgFromRepo synthesizes the legacy TenantGitConfig view of a repo row so
// the existing resolver (platform app → per-repo BYO override) applies
// unchanged.
func cfgFromRepo(r *types.TenantGitRepo) *types.TenantGitConfig {
	return &types.TenantGitConfig{
		OrgID: r.OrgID, Repo: r.Repo, CommitPolicy: r.CommitPolicy,
		BaseBranch: r.BaseBranch, GitHubApp: r.GitHubApp,
	}
}

func (s *Service) querier() db.Querier {
	if s.db != nil {
		return s.db.Pool
	}
	return nil
}

// inTx runs fn inside a DB transaction when a DB is wired; unit tests
// without a DB run fn directly against the pool-less store seam.
func (s *Service) inTx(ctx context.Context, fn func(q db.Querier) error) error {
	if s.db == nil {
		return fn(nil)
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error { return fn(tx) })
}

// recordAudit writes the audit event; a nil audit store (unit tests) skips.
func (s *Service) recordAudit(ctx context.Context, q db.Querier, orgID, actor, action, objectID string, payload map[string]any) error {
	if s.audit == nil {
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ev := &types.AuditEvent{
		OrgID: orgID, Actor: actor, Impersonator: impersonation.FromContext(ctx),
		Action: action, ObjectType: "tenant_git_repo", ObjectID: objectID,
		Payload: json.RawMessage(raw),
	}
	if err := impersonation.Stamp(ctx, ev); err != nil {
		return err
	}
	return s.audit.Record(ctx, q, ev)
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
