package clusterdex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/7K-Inari/inari-server/internal/addons"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/impersonation"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/renderer"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ClusterLister is the cluster registry seam.
type ClusterLister interface {
	ListClusters(ctx context.Context, orgID string) ([]types.Cluster, error)
}

// TeamLister is the tenancy seam feeding the ArgoCD RBAC group derivation.
type TeamLister interface {
	ListTeams(ctx context.Context, orgID string) ([]types.Team, error)
}

// BaselineSelector resolves a cluster's bound baseline repo selector
// (inventory.Store seam; "" = no repo registered).
type BaselineSelector interface {
	BaselineRepoSelector(ctx context.Context, q db.Querier, orgID, clusterID string) (string, error)
}

// RepoLister enumerates the org's registered repos (inventory.Store seam) so
// repos that lost ALL their matched clusters still get drained.
type RepoLister interface {
	ListGitRepos(ctx context.Context, q db.Querier, orgID string, teamIDs []string) ([]*types.TenantGitRepo, error)
}

// Queue is the agent command queue seam (agentgateway.Queue).
type Queue interface {
	Enqueue(ctx context.Context, cmd *types.AgentCommand) error
}

// Service renders and delivers the per-cluster Dex fan-out (see the package
// doc). Pure orchestration over the renderer + gitprovider + queue seams;
// the DB handle is only used to feed the querier-taking inventory seams and
// audit writes (nil in unit tests).
type Service struct {
	db        *db.DB
	cfg       Config
	clusters  ClusterLister
	teams     TeamLister
	baselines BaselineSelector
	repos     RepoLister
	git       *gitprovider.RepoResolver
	queue     Queue
	audit     *audit.Store
	renders   *renderer.Registry
	log       *slog.Logger
}

// NewService wires the module. queue may be nil (deliveries skipped);
// auditStore may be nil (audit writes skipped).
func NewService(d *db.DB, cfg Config, clusters ClusterLister, teams TeamLister,
	baselines BaselineSelector, repos RepoLister, git *gitprovider.RepoResolver,
	queue Queue, auditStore *audit.Store, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		db: d, cfg: cfg, clusters: clusters, teams: teams, baselines: baselines,
		repos: repos, git: git, queue: queue, audit: auditStore, log: log,
		renders: renderer.New(nil),
	}
}

func (s *Service) querier() db.Querier {
	if s.db != nil {
		return s.db.Pool
	}
	return nil
}

// RerenderOrg recomputes the org's Dex fan-out: selector evaluation over
// inventory labels, grouping by bound baseline repo, render + commit-on-drift
// per repo, and per-cluster appset delivery via the agent bridge. Idempotent:
// unchanged content produces no commits and no new queue rows.
// staleClusterNames carries names of hard-deleted clusters (no longer in the
// registry) so their overlay files are purged.
func (s *Service) RerenderOrg(ctx context.Context, orgID string, staleClusterNames ...string) error {
	// Automation acts via the tenant-scoped virtual user (plan §5.4): audit
	// stamping requires an impersonated identity for system actors.
	ctx = impersonation.WithImpersonator(ctx, impersonation.VirtualUser(orgID))

	clusters, err := s.clusters.ListClusters(ctx, orgID)
	if err != nil {
		return fmt.Errorf("clusterdex: list clusters: %w", err)
	}
	teams, err := s.teams.ListTeams(ctx, orgID)
	if err != nil {
		return fmt.Errorf("clusterdex: list teams: %w", err)
	}
	refs := make([]TeamRef, 0, len(teams))
	for _, t := range teams {
		refs = append(refs, TeamRef{RoleName: t.RoleName, GroupPath: t.KeycloakGroupPath})
	}
	groups, err := RBACGroupsFromTeams(refs)
	if err != nil {
		return err
	}
	// Config-level failures (e.g. a malformed Dex image override) are global
	// — they fail every repo identically — so they abort the pass loudly
	// (the outbox redelivers and dead-letters visibly) instead of being
	// logged once per repo.
	if _, err := s.appSetSpecs(); err != nil {
		return err
	}

	// Selector (engine-agnostic, decision D5): every active/degraded org
	// cluster gets the Dex baseline unless it carries the opt-out label.
	var matched, optedOut []types.Cluster
	for _, c := range clusters {
		if c.State != types.ClusterStateActive && c.State != types.ClusterStateDegraded {
			continue
		}
		if c.Labels[DisabledLabel] == DisabledLabelValue {
			optedOut = append(optedOut, c)
			continue
		}
		matched = append(matched, c)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].ID < matched[j].ID })

	// Group matched clusters by bound baseline repo (parent plan §2.3:
	// fleet renders resolve per-cluster against the bound baseline).
	byRepo := map[string][]types.Cluster{}
	for _, c := range matched {
		sel, err := s.baselines.BaselineRepoSelector(ctx, s.querier(), orgID, c.ID)
		if err != nil {
			return fmt.Errorf("clusterdex: baseline selector for %s: %w", c.ID, err)
		}
		if sel == "" {
			s.log.Warn("clusterdex: cluster has no baseline repo; skipped", "cluster", c.ID)
			continue
		}
		byRepo[sel] = append(byRepo[sel], c)
	}

	repos, err := s.repos.ListGitRepos(ctx, s.querier(), orgID, nil)
	if err != nil {
		return fmt.Errorf("clusterdex: list repos: %w", err)
	}
	for _, repo := range repos {
		if repo.Scope != types.GitRepoScopePlatform {
			continue
		}
		if err := s.reconcileRepo(ctx, orgID, repo, byRepo[repo.ID], groups, clusters, optedOut, staleClusterNames); err != nil {
			// One bad repo must not starve the others; the outbox redelivers.
			s.log.Warn("clusterdex: reconcile repo", "repo", repo.Repo, "error", err)
		}
	}
	return nil
}

// reconcileRepo renders the full dex + argocd-config file set for one
// baseline repo, commits on drift per the repo's commit policy, purges stale
// per-cluster overlays, and delivers per-cluster appset views.
func (s *Service) reconcileRepo(ctx context.Context, orgID string, repo *types.TenantGitRepo,
	members []types.Cluster, groups RBACGroups, allClusters, optedOut []types.Cluster, staleNames []string) error {

	_, provider, _, err := s.git.ResolveRepo(ctx, orgID, repo.ID)
	if err != nil {
		return fmt.Errorf("resolve repo: %w", err)
	}

	// Pre-commit state: which overlays exist (prior-management proof for
	// opt-out drains) and whether the repo is managed at all.
	existingDexSet, err := provider.ReadFile(ctx, repo.Repo, repo.BaseBranch, repoPathDex+"/applicationset.yaml")
	if err != nil {
		return fmt.Errorf("read appset: %w", err)
	}
	if len(members) == 0 && existingDexSet == "" {
		return nil // never managed and nothing matched: leave the repo alone
	}

	files, err := s.renderRepoFiles(ctx, repo, members, groups)
	if err != nil {
		return err
	}

	// Stale overlay paths: overlays of clusters that are known but not in
	// this repo's member set, plus hard-deleted clusters from the event.
	memberNames := map[string]bool{}
	for _, c := range members {
		memberNames[c.Name] = true
	}
	var stalePaths []string
	seen := map[string]bool{}
	addStale := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		stalePaths = append(stalePaths, overlayPaths(name)...)
	}
	for _, c := range allClusters {
		if !memberNames[c.Name] {
			addStale(c.Name)
		}
	}
	for _, n := range staleNames {
		addStale(n)
	}

	// Capture pre-commit overlay existence for the opt-out drain decision.
	optedOutHere := map[string]bool{}
	for _, c := range optedOut {
		sel, err := s.baselines.BaselineRepoSelector(ctx, s.querier(), orgID, c.ID)
		if err != nil || sel != repo.ID {
			continue
		}
		had, err := provider.ReadFile(ctx, repo.Repo, repo.BaseBranch, dexOverlayPath(c.Name))
		if err != nil {
			return fmt.Errorf("read overlay: %w", err)
		}
		optedOutHere[c.ID] = had != ""
	}

	// Diff desired vs current.
	var changed []gitprovider.File
	for _, f := range files {
		cur, err := provider.ReadFile(ctx, repo.Repo, repo.BaseBranch, f.Path)
		if err != nil {
			return fmt.Errorf("read %s: %w", f.Path, err)
		}
		if cur != string(f.Content) {
			changed = append(changed, f)
		}
	}
	var deletions []string
	for _, p := range stalePaths {
		cur, err := provider.ReadFile(ctx, repo.Repo, repo.BaseBranch, p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		if cur != "" {
			deletions = append(deletions, p)
		}
	}

	if len(changed) > 0 {
		message := fmt.Sprintf("clusterdex: sync dex fan-out (%d files)", len(changed))
		if _, err := commitPerPolicy(ctx, provider, repo, message, changed); err != nil {
			return fmt.Errorf("commit: %w", err)
		}
	}
	// Deletions ride direct commits only (the PR path cannot express them);
	// a stale overlay is harmless — no appset element references it.
	if len(deletions) > 0 && repo.CommitPolicy != types.CommitPolicyPullRequest {
		if _, err := provider.DeleteFiles(ctx, repo.Repo, repo.BaseBranch, deletions, "clusterdex: purge stale cluster overlays"); err != nil {
			return fmt.Errorf("delete stale overlays: %w", err)
		}
	}
	if len(changed) > 0 || len(deletions) > 0 {
		s.recordAudit(ctx, orgID, repo, len(members), len(changed), len(deletions))
	}

	// Delivery gate: deliver only when the repo's committed state matches
	// the desired appsets (direct: just committed; PR policy: after merge —
	// the git.webhook.pr_merged event re-triggers this pass). Both appsets
	// must be live: delivering a view whose $values overlays are not on the
	// base branch yet would render broken children.
	for _, path := range []string{repoPathDex, repoPathArgoConfig} {
		desired := desiredGitContent(files, path+"/applicationset.yaml")
		if desired == "" {
			continue // argocd-config disabled (no chart pin)
		}
		current, err := provider.ReadFile(ctx, repo.Repo, repo.BaseBranch, path+"/applicationset.yaml")
		if err != nil {
			return fmt.Errorf("re-read %s appset: %w", path, err)
		}
		if current != desired {
			return nil // membership not live in git yet
		}
	}
	return s.deliver(ctx, repo, members, optedOut, optedOutHere)
}

// deliver enqueues per-cluster appset views via the agent bridge. Each
// matched cluster receives the appsets containing only its OWN element (the
// appset controller is cluster-local; the full membership list lives in git
// for review). Opted-out clusters that were previously managed receive the
// empty-element view, which prunes their Dex via the resources finalizer.
func (s *Service) deliver(ctx context.Context, repo *types.TenantGitRepo, members, optedOut []types.Cluster, optedOutHere map[string]bool) error {
	if s.queue == nil {
		return nil
	}
	for _, c := range members {
		if err := s.deliverCluster(ctx, repo, c, true); err != nil {
			return err
		}
	}
	for _, c := range optedOut {
		if !optedOutHere[c.ID] {
			continue // never managed by this repo
		}
		if err := s.deliverCluster(ctx, repo, c, false); err != nil {
			return err
		}
	}
	return nil
}

// deliverCluster renders the single-cluster view of both appsets (members
// empty for an opt-out drain) and enqueues them. The queue row ID is
// content-versioned: unchanged content dedupes (ON CONFLICT DO NOTHING),
// changed content is a new row and redelivers.
func (s *Service) deliverCluster(ctx context.Context, repo *types.TenantGitRepo, cluster types.Cluster, asMember bool) error {
	members := []types.Cluster{}
	if asMember {
		members = []types.Cluster{cluster}
	}
	specs, err := s.appSetSpecs()
	if err != nil {
		return err
	}
	for _, spec := range specs {
		files, err := s.renderAppSet(ctx, spec, repo, members)
		if err != nil {
			return err
		}
		manifest := desiredContent(files, spec.path+"/applicationset.yaml")
		if manifest == "" {
			continue // argocd-config disabled (no chart pin)
		}
		sum := sha256.Sum256([]byte(manifest))
		name := renderer.PrefixAddonSet + "-" + spec.id
		queueID := fmt.Sprintf("register-argocd-appset:%s:%s:%s", name, cluster.Name, hex.EncodeToString(sum[:])[:8])
		if err := s.enqueue(ctx, cluster.ID, queueID, addons.RegisterAppSetEventType, map[string]any{
			"commandId": queueID, "name": name, "namespace": "argocd", "manifest": manifest,
		}); err != nil {
			return err
		}
	}
	return nil
}

// appSetSpec describes one of the two fan-out appsets.
type appSetSpec struct {
	id              string // renderer ID; appset name = inari-addonset-<id>
	workload        string // overlay path segment (clusters/<c>/<workload>/values.yaml)
	path            string // repo render root
	desc            types.SourceDescriptor
	appNameTemplate string
	releaseName     string
	namespace       string
	syncOptions     []string
	baseValues      map[string]any
}

// appSetSpecs builds the two fan-out specs for the current config. The
// argocd-config spec is absent when the platform chart pin is unconfigured.
// A malformed Dex image override (config error) is a hard error: silently
// dropping the dex appset would stall the delivery gate forever with the
// stale committed manifest left in place.
func (s *Service) appSetSpecs() ([]appSetSpec, error) {
	dexBase, err := dexBaseValues(s.cfg)
	if err != nil {
		return nil, fmt.Errorf("clusterdex: dex base values: %w", err)
	}
	specs := []appSetSpec{{
		id:       workloadDex,
		workload: workloadDex,
		path:     repoPathDex,
		desc: types.SourceDescriptor{Kind: types.SourceKindHelm, Helm: &types.HelmSource{
			RepoURL: DexChartRepoURL, Chart: DexChartName, Version: s.cfg.dexChartVersion(),
		}},
		appNameTemplate: appNameTplDex,
		releaseName:     appNameTplDex,
		namespace:       DexNamespace,
		syncOptions:     []string{"CreateNamespace=true"},
		baseValues:      dexBase,
	}}
	if s.cfg.PlatformChartVersion == "" {
		s.log.Warn("clusterdex: platform chart version unconfigured; argocd-config fan-out skipped")
	} else {
		specs = append(specs, appSetSpec{
			id:       workloadArgoConfig,
			workload: workloadArgoConfig,
			path:     repoPathArgoConfig,
			desc: types.SourceDescriptor{Kind: types.SourceKindHelm, Helm: &types.HelmSource{
				RepoURL: s.cfg.PlatformChartRepoURL, Chart: s.cfg.PlatformChartName, Version: s.cfg.PlatformChartVersion,
			}},
			appNameTemplate: appNameTplArgo,
			releaseName:     appNameTplArgo,
			namespace:       s.cfg.argoCDNamespace(),
			baseValues:      argoConfigBaseValues(s.cfg),
		})
	}
	return specs, nil
}

// renderAppSet renders one appset (base values + applicationset.yaml) for
// the given cluster membership, embedding the repo's real clone URL and
// branch in the $values ref.
func (s *Service) renderAppSet(ctx context.Context, spec appSetSpec, repo *types.TenantGitRepo, members []types.Cluster) ([]renderer.RenderedFile, error) {
	targets := make([]renderer.ClusterTarget, 0, len(members))
	for _, c := range members {
		targets = append(targets, renderer.ClusterTarget{
			ID: c.ID, Name: c.Name,
			Fields: map[string]string{"clusterID": c.ID, "dexAppName": AppName(c.ID)},
		})
	}
	values, err := json.Marshal(spec.baseValues)
	if err != nil {
		return nil, err
	}
	return s.renders.Render(ctx, spec.desc, renderer.RenderParams{
		Name: spec.workload, Namespace: spec.namespace,
		ID: spec.id, DeployMode: types.AddonDeployModeApplicationSet,
		Clusters: targets,
		// Server-owned baseline: prune + cascade-delete (no adoption
		// semantics — this is not brownfield content).
		Prune:           true,
		CascadeDelete:   true,
		SyncOptions:     spec.syncOptions,
		Values:          values,
		RepoURL:         orchestrator.RepoURL(repo.Repo),
		BaseBranch:      repo.BaseBranch,
		Path:            spec.path,
		AppNameTemplate: spec.appNameTemplate,
		ReleaseName:     spec.releaseName,
	})
}

// renderRepoFiles renders the full file set for one baseline repo: both
// appsets (full membership — the review/audit form), their base values, and
// the per-cluster overlays.
func (s *Service) renderRepoFiles(ctx context.Context, repo *types.TenantGitRepo, members []types.Cluster, groups RBACGroups) ([]gitprovider.File, error) {
	var out []gitprovider.File
	specs, err := s.appSetSpecs()
	if err != nil {
		return nil, err
	}
	for _, spec := range specs {
		files, err := s.renderAppSet(ctx, spec, repo, members)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			out = append(out, gitprovider.File{Path: f.Path, Content: f.Content})
		}
	}
	for _, c := range members {
		dexOv, err := dexOverlay(c.ID)
		if err != nil {
			return nil, err
		}
		raw, err := yamlMarshal(dexOv)
		if err != nil {
			return nil, err
		}
		out = append(out, gitprovider.File{Path: dexOverlayPath(c.Name), Content: raw})

		if s.cfg.PlatformChartVersion != "" {
			argoOv, err := argoConfigOverlay(s.cfg, c.ID, c.Name, groups)
			if err != nil {
				return nil, err
			}
			out = append(out, gitprovider.File{Path: argoConfigOverlayPath(c.Name), Content: argoOv})
		}
	}
	return out, nil
}

func overlayPaths(clusterName string) []string {
	return []string{dexOverlayPath(clusterName), argoConfigOverlayPath(clusterName)}
}

func dexOverlayPath(clusterName string) string {
	return "clusters/" + clusterName + "/" + workloadDex + "/values.yaml"
}

func argoConfigOverlayPath(clusterName string) string {
	return "clusters/" + clusterName + "/" + workloadArgoConfig + "/values.yaml"
}

// desiredContent extracts one file's content from a rendered set.
func desiredContent(files []renderer.RenderedFile, path string) string {
	for _, f := range files {
		if f.Path == path {
			return string(f.Content)
		}
	}
	return ""
}

// desiredGitContent extracts one file's content from a committed file set.
func desiredGitContent(files []gitprovider.File, path string) string {
	for _, f := range files {
		if f.Path == path {
			return string(f.Content)
		}
	}
	return ""
}

// commitPerPolicy writes files per the repo's commit policy (direct commit
// or PR), mirroring the addons convention.
func commitPerPolicy(ctx context.Context, git gitprovider.Provider, repo *types.TenantGitRepo, message string, files []gitprovider.File) (*gitprovider.Result, error) {
	if repo.CommitPolicy == types.CommitPolicyPullRequest {
		return git.OpenPR(ctx, repo.Repo, repo.BaseBranch, message, "", files)
	}
	return git.CommitFiles(ctx, repo.Repo, repo.BaseBranch, files, message)
}

// enqueue marshals one bridge payload into a durable agent command (same
// protojson-Any envelope as the addons registrations).
func (s *Service) enqueue(ctx context.Context, clusterID, queueID, eventType string, fields map[string]any) error {
	payload, err := structpb.NewStruct(fields)
	if err != nil {
		return err
	}
	any, err := anypb.New(payload)
	if err != nil {
		return err
	}
	raw, err := protojson.Marshal(any)
	if err != nil {
		return err
	}
	return s.queue.Enqueue(ctx, &types.AgentCommand{
		ID: queueID, ClusterID: clusterID, Type: eventType, Payload: raw,
	})
}

// recordAudit writes the render audit event (best-effort w.r.t. the render
// itself: the commit already happened).
func (s *Service) recordAudit(ctx context.Context, orgID string, repo *types.TenantGitRepo, members, changed, deleted int) {
	if s.audit == nil {
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"repo": repo.Repo, "repoId": repo.ID, "matchedClusters": members,
		"filesChanged": changed, "filesDeleted": deleted,
	})
	ev := &types.AuditEvent{
		OrgID: orgID, Actor: impersonation.SystemActor("clusterdex"),
		Action: "clusterdex.rendered", ObjectType: "tenant_git_repo", ObjectID: repo.ID,
		Payload: payload,
	}
	if err := impersonation.Stamp(ctx, ev); err != nil {
		s.log.Warn("clusterdex: audit stamp", "error", err)
		return
	}
	if err := s.audit.Record(ctx, s.querier(), ev); err != nil {
		s.log.Warn("clusterdex: audit record", "error", err)
	}
}
