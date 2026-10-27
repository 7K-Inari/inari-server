// Package orchestrator turns deploy requests into desired state (plan §5.2):
// render the RGD instance → commit/PR to the platform-owned
// <tenant>-inari-state repo (PR vs direct commit is per-tenant policy) →
// dispatch register-argocd-app via the agent gateway. Git is behind the
// gitprovider.Provider abstraction from day one (GitHub App first, never
// PATs, §12.1/2).
package orchestrator

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
	"gopkg.in/yaml.v3"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/impersonation"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/renderer"
	"github.com/7K-Inari/inari-server/internal/types"
)

// CatalogResolver is the catalog seam the orchestrator needs.
type CatalogResolver interface {
	GetItemByID(ctx context.Context, itemID string) (*types.CatalogItem, error)
	EffectiveVersion(ctx context.Context, orgID, itemID, channel string) (string, error)
	GetVersion(ctx context.Context, itemID, version string) (*types.CatalogItemVersion, error)
	// EnsureVisible enforces per-tenant/cluster catalog visibility policies
	// (an item hidden from the tenant reads as not-found).
	EnsureVisible(ctx context.Context, orgID, clusterID, itemID string) error
}

// ClusterResolver is the cluster registry seam.
type ClusterResolver interface {
	GetCluster(ctx context.Context, id string) (*types.Cluster, error)
}

// Gate is the approvals seam.
type Gate interface {
	Gate(ctx context.Context, in approvals.GateInput) (*approvals.GateResult, error)
}

// PolicyChecker is the Policy Service seam (plan §5.11): PreFlight runs
// request-time OPA checks before the approval gate; RenderCheck runs
// render-time manifest checks before anything reaches tenant Git.
type PolicyChecker interface {
	PreFlight(ctx context.Context, in PolicyInput) (*types.PolicyDecision, error)
	RenderCheck(ctx context.Context, orgID string, manifests ...[]byte) (*types.PolicyDecision, error)
}

// PolicyInput is the orchestrator-side pre-flight input (mapped onto the
// Policy Service's own input type at the wiring seam).
type PolicyInput struct {
	OrgID               string
	ItemID              string
	Version             string
	ClusterID           string
	Spec                json.RawMessage
	Requester           string
	ClusterLabels       map[string]string
	ClusterDistribution string
}

// PolicyViolationError carries the blocking decision (reason + remediation)
// to the HTTP layer, which answers 422 with the full decision payload.
type PolicyViolationError struct {
	Decision *types.PolicyDecision
}

func (e *PolicyViolationError) Error() string {
	if e.Decision == nil || len(e.Decision.Violations) == 0 {
		return "orchestrator: policy violation"
	}
	parts := make([]string, 0, len(e.Decision.Violations))
	for _, v := range e.Decision.Violations {
		parts = append(parts, fmt.Sprintf("%s: %s (remediation: %s)", v.Rule, v.Reason, v.Remediation))
	}
	return "orchestrator: policy violation: " + strings.Join(parts, "; ")
}

// Queue is the agent command queue seam (agentgateway.Queue).
type Queue interface {
	Enqueue(ctx context.Context, cmd *types.AgentCommand) error
}

// ErrNoGitConfig is returned when the tenant has no state repo configured.
var ErrNoGitConfig = fmt.Errorf("orchestrator: tenant has no git config (provisioned by the tenant zone factory)")

// ErrClusterNotActive blocks deploys to non-active clusters (§5.11 cordon).
var ErrClusterNotActive = fmt.Errorf("orchestrator: cluster is not active")

// ErrClusterMismatch is returned when the cluster belongs to another tenant
// (reads as not-found to the caller).
var ErrClusterMismatch = fmt.Errorf("orchestrator: cluster does not belong to tenant")

// ErrInstanceExists is returned when a deploy reuses an existing instance name.
var ErrInstanceExists = fmt.Errorf("orchestrator: instance already exists")

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

// DeployRequest is one catalog deploy/update intent.
type DeployRequest struct {
	OrgID     string
	ClusterID string
	ItemID    string
	Version   string // empty = resolve pin/latest
	Channel   string // default "stable"
	Name      string // instance name; defaults to item name + short id
	Namespace string // destination namespace; default "default"
	OwnerTeam string
	Spec      json.RawMessage
	Requester string
	// RepoID selects the tenant_git_repos row the manifests are committed
	// to (Feature A); empty = the org's default repo.
	RepoID string
}

// DeployResult reports the deploy outcome.
type DeployResult struct {
	InstanceID string
	Version    string
	// Status is "deploying" or "pending_approval".
	Status     string
	ApprovalID string
	CommitSHA  string
	PRURL      string
}

// Service is the Orchestrator module.
type Service struct {
	db        *db.DB
	instances *inventory.Store
	catalog   CatalogResolver
	clusters  ClusterResolver
	gate      Gate
	policy    PolicyChecker // nil = no policy enforcement
	queue     Queue
	git       gitprovider.Resolver
	// gitRepos is the repo-aware resolver (Feature A). nil = legacy
	// single-repo mode: deploys resolve via git.ForTenant(GitConfig(org)).
	gitRepos *gitprovider.RepoResolver
	audit    *audit.Store
	// renders is the source-agnostic render pipeline (Feature C, parent
	// plan §6): deploy/update/rollback build a kro SourceDescriptor and
	// render through the registry instead of calling render.go directly.
	// The RGD resolver is catalog-backed (ref format "<itemID>@<version>").
	renders *renderer.Registry
}

func NewService(d *db.DB, instances *inventory.Store, catalog CatalogResolver, clusters ClusterResolver,
	gate Gate, queue Queue, git gitprovider.Resolver, auditStore *audit.Store) *Service {
	s := &Service{
		db: d, instances: instances, catalog: catalog, clusters: clusters,
		gate: gate, queue: queue, git: git, audit: auditStore,
	}
	s.renders = renderer.New(s.resolveRGD)
	return s
}

// rgdRef is the catalog-backed RGD reference carried in kro source
// descriptors: "<itemID>@<version>".
func rgdRef(itemID, version string) string { return itemID + "@" + version }

// resolveRGD resolves a kro descriptor's RGDRef against the catalog (the
// renderer's ResolveRGDFunc seam). The version payload's "rgd" key holds
// the inline RGD YAML (ociync platform/kro package convention).
func (s *Service) resolveRGD(ctx context.Context, ref string) ([]byte, error) {
	itemID, version, ok := strings.Cut(ref, "@")
	if !ok || itemID == "" || version == "" {
		return nil, fmt.Errorf("orchestrator: malformed RGD ref %q (want <itemID>@<version>)", ref)
	}
	ver, err := s.catalog.GetVersion(ctx, itemID, version)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: resolve RGD %q: %w", ref, err)
	}
	var payload struct {
		RGD string `json:"rgd"`
	}
	if err := json.Unmarshal(ver.Payload, &payload); err != nil {
		return nil, fmt.Errorf("orchestrator: parse version payload: %w", err)
	}
	if payload.RGD == "" {
		return nil, fmt.Errorf("orchestrator: catalog version %s has no rgd payload", ref)
	}
	return []byte(payload.RGD), nil
}

// WithPolicyChecker attaches the Policy Service seam (main wiring).
func (s *Service) WithPolicyChecker(p PolicyChecker) *Service { s.policy = p; return s }

// WithRepoResolver attaches the repo-aware git resolver (Feature A main
// wiring). Once set, deploy/update/delete writes resolve the target repo
// row (selector or the instance's recorded repo) through the registry.
func (s *Service) WithRepoResolver(rr *gitprovider.RepoResolver) *Service { s.gitRepos = rr; return s }

// preFlight runs request-time policy checks; a blocking decision yields a
// *PolicyViolationError.
func (s *Service) preFlight(ctx context.Context, in PolicyInput) error {
	if s.policy == nil {
		return nil
	}
	decision, err := s.policy.PreFlight(ctx, in)
	if err != nil {
		return err
	}
	if decision != nil && !decision.Allow {
		return &PolicyViolationError{Decision: decision}
	}
	return nil
}

// renderCheck runs render-time policy checks on rendered manifests.
func (s *Service) renderCheck(ctx context.Context, orgID string, manifests ...[]byte) error {
	if s.policy == nil {
		return nil
	}
	decision, err := s.policy.RenderCheck(ctx, orgID, manifests...)
	if err != nil {
		return err
	}
	if decision != nil && !decision.Allow {
		return &PolicyViolationError{Decision: decision}
	}
	return nil
}

// Deploy turns a deploy request into desired state. Request-time policy
// (PreFlight) runs before the approval gate; when the item's approval
// policy requires review, an approval request is created and the deploy
// resumes automatically on approval (see ResumeHandler).
func (s *Service) Deploy(ctx context.Context, req DeployRequest) (*DeployResult, error) {
	cluster, err := s.clusters.GetCluster(ctx, req.ClusterID)
	if err != nil {
		return nil, err
	}
	if cluster.OrgID != req.OrgID {
		return nil, ErrClusterMismatch
	}
	if cluster.State != types.ClusterStateActive && cluster.State != types.ClusterStateDegraded {
		return nil, ErrClusterNotActive
	}
	if err := s.catalog.EnsureVisible(ctx, req.OrgID, req.ClusterID, req.ItemID); err != nil {
		return nil, err
	}
	item, err := s.catalog.GetItemByID(ctx, req.ItemID)
	if err != nil {
		return nil, err
	}
	version := req.Version
	if version == "" {
		channel := req.Channel
		if channel == "" {
			channel = "stable"
		}
		version, err = s.catalog.EffectiveVersion(ctx, req.OrgID, req.ItemID, channel)
		if err != nil {
			return nil, err
		}
	}

	if err := s.preFlight(ctx, PolicyInput{
		OrgID: req.OrgID, ItemID: req.ItemID, Version: version,
		ClusterID: req.ClusterID, Spec: req.Spec, Requester: req.Requester,
		ClusterLabels: cluster.Labels, ClusterDistribution: cluster.Distribution,
	}); err != nil {
		return nil, err
	}

	gate, err := s.gate.Gate(ctx, approvals.GateInput{
		OrgID: req.OrgID, Item: item, Version: version, ClusterID: req.ClusterID,
		Spec: req.Spec, Requester: req.Requester, Name: req.Name, Namespace: req.Namespace,
		OwnerTeam: req.OwnerTeam, Channel: req.Channel, RepoID: req.RepoID,
	})
	if err != nil {
		return nil, err
	}
	if !gate.Approved {
		return &DeployResult{Status: "pending_approval", ApprovalID: gate.ApprovalID, Version: version}, nil
	}
	return s.apply(ctx, req, item, version, nil)
}

// apply renders + commits + enqueues + records the instance. When existing
// is non-nil this is an upgrade of that instance.
func (s *Service) apply(ctx context.Context, req DeployRequest, item *types.CatalogItem, version string, existing *types.ResourceInstance) (*DeployResult, error) {
	return s.applyWithEvent(ctx, req, item, version, existing, "", false)
}

// gitTarget is the resolved repo a write lands in: the registry row when
// the repo-aware resolver is wired, otherwise the legacy git-config
// projection (default repo).
type gitTarget struct {
	repoID     string // registry row id; empty in legacy mode
	repo       string // owner/name
	branch     string
	policy     types.CommitPolicy
	provider   gitprovider.Provider
	authInfo   *gitprovider.AuthInfo
	ensureRepo bool // legacy mode only: registered rows skip EnsureRepo
}

// resolveTarget resolves the repo a deploy/mutation writes to. With the
// repo-aware resolver wired, selector ("" = default) goes through the
// registry; otherwise the legacy git-config path runs unchanged.
func (s *Service) resolveTarget(ctx context.Context, orgID, selector string) (*gitTarget, error) {
	if s.gitRepos != nil {
		row, p, info, err := s.gitRepos.ResolveRepo(ctx, orgID, selector)
		if errors.Is(err, inventory.ErrRepoNotFound) && (selector == "" || selector == gitprovider.RepoSelectorDefault) {
			// Back-compat: no default row reads as "no git config" (409).
			return nil, ErrNoGitConfig
		}
		if err != nil {
			return nil, err
		}
		return &gitTarget{
			repoID: row.ID, repo: row.Repo, branch: row.BaseBranch,
			policy: row.CommitPolicy, provider: p, authInfo: info,
		}, nil
	}
	gitCfg, err := s.instances.GitConfig(ctx, s.db.Pool, orgID)
	if err != nil {
		return nil, err
	}
	if gitCfg == nil {
		return nil, ErrNoGitConfig
	}
	git, authInfo, err := s.git.ForTenant(ctx, gitCfg)
	if err != nil {
		return nil, err
	}
	return &gitTarget{
		repo: gitCfg.Repo, branch: gitCfg.BaseBranch, policy: gitCfg.CommitPolicy,
		provider: git, authInfo: authInfo, ensureRepo: true,
	}, nil
}

// applyWithEvent is apply with an overridable outbox event type and, for
// spec-only updates (same version), spec persistence. An empty eventType
// keeps the default (deploy.requested / instance.upgraded).
func (s *Service) applyWithEvent(ctx context.Context, req DeployRequest, item *types.CatalogItem, version string, existing *types.ResourceInstance, eventType string, specUpdate bool) (*DeployResult, error) {
	// Fail fast on an unknown catalog version (and preserve the historical
	// error precedence over git-target resolution); the RGD itself is
	// resolved lazily by the renderer's catalog-backed resolver.
	if _, err := s.catalog.GetVersion(ctx, req.ItemID, version); err != nil {
		return nil, err
	}
	selector := req.RepoID
	if existing != nil {
		// Mutations always land in the instance's recorded repo; an
		// explicit selector that disagrees is rejected by the caller
		// (ErrRepoMismatch) before reaching apply.
		selector = existing.RepoID
	}
	target, err := s.resolveTarget(ctx, req.OrgID, selector)
	if err != nil {
		return nil, err
	}
	git, authInfo := target.provider, target.authInfo
	if target.ensureRepo {
		if _, err := git.EnsureRepo(ctx, target.repo); err != nil {
			return nil, err
		}
	}

	instanceID := req.Name
	if existing != nil {
		instanceID = existing.ID
	}
	if instanceID == "" {
		instanceID = item.Name + "-" + uuid.NewString()[:8]
	}
	name := instanceID
	namespace := req.Namespace
	if namespace == "" {
		namespace = "default"
	}
	if existing != nil {
		// Name/namespace are immutable across upgrades.
		name = existing.ResourceRef.Name
		if existing.ResourceRef.Namespace != "" {
			namespace = existing.ResourceRef.Namespace
		}
	}

	// Render through the source-agnostic pipeline (kro handler): the
	// descriptor carries the catalog-backed RGD ref + the user spec; the
	// handler materializes instance.yaml and the git-path Application —
	// byte-identical to the pre-migration render.go output (parity-pinned
	// by render_parity_test.go and the renderer golden tests).
	desc := types.SourceDescriptor{
		Kind: types.SourceKindKRO,
		KRO:  &types.KROSource{RGDRef: rgdRef(req.ItemID, version), Instance: req.Spec},
	}
	path := RepoPath(req.ClusterID, req.ItemID, instanceID)
	// NOTE: for team-repo deploys the tenant ArgoCD needs repo-creds for
	// that repo; root-app attachment is Feature B. The orchestrator does
	// not block team-repo deploys meanwhile.
	rendered, err := s.renders.Render(ctx, desc, renderer.RenderParams{
		Name: name, Namespace: namespace,
		ID: instanceID, AppPrefix: renderer.PrefixInstance,
		DeployMode: types.AddonDeployModeApplication,
		Clusters:   []renderer.ClusterTarget{{ID: req.ClusterID, Name: req.ClusterID}},
		Prune:      true, // instance deploys keep their historical prune-on policy
		Project:    "default",
		RepoURL:    RepoURL(target.repo), BaseBranch: target.branch,
		Path: path,
	})
	if err != nil {
		return nil, err
	}
	var manifest []byte
	files := make([]gitprovider.File, 0, len(rendered))
	for _, f := range rendered {
		if strings.HasSuffix(f.Path, "/instance.yaml") {
			manifest = f.Content
		}
		files = append(files, gitprovider.File{Path: f.Path, Content: f.Content})
	}
	if manifest == nil {
		return nil, fmt.Errorf("orchestrator: kro render produced no instance manifest")
	}
	if err := s.renderCheck(ctx, req.OrgID, manifest); err != nil {
		return nil, err
	}

	message := fmt.Sprintf("deploy %s@%s to %s (instance %s)", req.ItemID, version, req.ClusterID, instanceID)
	var gitResult *gitprovider.Result
	if target.policy == types.CommitPolicyPullRequest {
		gitResult, err = git.OpenPR(ctx, target.repo, target.branch, message, "", files)
	} else {
		gitResult, err = git.CommitFiles(ctx, target.repo, target.branch, files, message)
	}
	if err != nil {
		return nil, fmt.Errorf("orchestrator: git write: %w", err)
	}

	// For pull-request policy the app registers after the PR merges (M2:
	// documented gap; the merge webhook wiring lands with Fleet Manager).
	if gitResult.PRURL == "" {
		if err := s.enqueueAppRegistration(ctx, req.ClusterID, instanceID, target, path, namespace); err != nil {
			return nil, err
		}
	}

	state := types.InstanceStateDeploying
	if existing != nil {
		state = types.InstanceStateUpgrading
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if existing == nil {
			inst := &types.ResourceInstance{
				ID: instanceID, OrgID: req.OrgID, ClusterID: req.ClusterID,
				CatalogItemID: req.ItemID, Version: version, OwnerTeam: req.OwnerTeam,
				Spec:        req.Spec,
				ResourceRef: types.ResourceRef{Group: "kro.run", Kind: kindOf(manifest), Name: name, Namespace: namespace},
				Health:      "unknown", State: state, ManagementMode: types.ManagementModeAdopt,
				CommitSHA: gitResult.CommitSHA, PRURL: gitResult.PRURL, RepoID: target.repoID, Generation: 1,
			}
			if err := s.instances.Create(ctx, tx, inst); err != nil {
				if isUniqueViolation(err) {
					return ErrInstanceExists
				}
				return err
			}
		} else if specUpdate {
			if err := s.instances.MarkSpecUpdated(ctx, tx, instanceID, req.Spec, gitResult.CommitSHA, gitResult.PRURL, target.repoID, state); err != nil {
				return err
			}
		} else if err := s.instances.MarkDeployed(ctx, tx, instanceID, version, gitResult.CommitSHA, gitResult.PRURL, target.repoID, state, true); err != nil {
			return err
		}
		ev := &types.AuditEvent{
			OrgID: req.OrgID, Actor: req.Requester, Impersonator: impersonation.FromContext(ctx), Action: "deploy.requested",
			ObjectType: "resource_instance", ObjectID: instanceID,
			Payload: json.RawMessage(fmt.Sprintf(`{"item":%q,"version":%q,"cluster":%q,"authModel":%q,"installationId":%d,"apiBase":%q}`,
				req.ItemID, version, req.ClusterID, authInfo.Model, authInfo.InstallationID, authInfo.APIBase)),
		}
		if err := impersonation.Stamp(ctx, ev); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, ev); err != nil {
			return err
		}
		if eventType == "" {
			eventType = types.EventDeployRequested
			if existing != nil {
				eventType = types.EventInstanceUpgraded
			}
		}
		return audit.AppendOutbox(ctx, tx, req.OrgID, eventType, types.DeployRequestedPayload{
			OrgID: req.OrgID, InstanceID: instanceID, ItemID: req.ItemID, ClusterID: req.ClusterID,
			Version: version, CommitSHA: gitResult.CommitSHA, PRURL: gitResult.PRURL,
			AuthModel: string(authInfo.Model), InstallationID: authInfo.InstallationID, APIBase: authInfo.APIBase,
			RepoID: target.repoID, Repo: target.repo,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("orchestrator: record deploy: %w", err)
	}
	return &DeployResult{
		InstanceID: instanceID, Version: version, Status: string(state),
		CommitSHA: gitResult.CommitSHA, PRURL: gitResult.PRURL,
	}, nil
}

// enqueueAppRegistration dispatches register-argocd-app to the cluster's
// agent (command ID = instance ID + generation → idempotent re-delivery).
func (s *Service) enqueueAppRegistration(ctx context.Context, clusterID, instanceID string, target *gitTarget, path, namespace string) error {
	cmd := &agentv1.RegisterArgoCDApp{
		CommandId: instanceID,
		// Lowercased: ULIDs are uppercase, not RFC 1123-valid on a real
		// apiserver; must match the renderer's appName.
		Name:    "inari-" + strings.ToLower(instanceID),
		Project: "default",
		Source: &agentv1.ApplicationSource{
			RepoUrl:        RepoURL(target.repo),
			Path:           path,
			TargetRevision: target.branch,
		},
		DestinationServer:    "https://kubernetes.default.svc",
		DestinationNamespace: namespace,
		SyncPolicy:           &agentv1.SyncPolicy{Automated: true, SelfHeal: true, Prune: true},
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
		ID:        "register-argocd-app:" + instanceID,
		ClusterID: clusterID,
		Type:      agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_REGISTER_ARGOCD_APP),
		Payload:   raw,
	})
}

// FinalizePRMerge completes a pull_request-policy deploy whose PR merged
// (gitwebhook.MergeFinalizer, closing the gap noted in applyWithEvent):
// the merge SHA becomes the instance's commit and the deferred ArgoCD
// registration is enqueued. found=false means no instance awaits that PR
// URL (already finalized, superseded, or not ours) — the caller treats it
// as an idempotent ack.
func (s *Service) FinalizePRMerge(ctx context.Context, orgID, prURL, mergeSHA string) (bool, error) {
	// Automation acts via the tenant-scoped virtual user (plan §5.4):
	// audit stamping requires an impersonated identity for system actors.
	ctx = impersonation.WithImpersonator(ctx, impersonation.VirtualUser(orgID))
	inst, err := s.instances.FindInstanceByPRURL(ctx, s.db.Pool, orgID, prURL)
	if errors.Is(err, inventory.ErrInstanceNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	target, err := s.resolveTarget(ctx, orgID, inst.RepoID)
	if err != nil {
		return false, err
	}
	// Enqueue before marking: the command ID is deterministic
	// (register-argocd-app:<instanceID>), so a crash after enqueue but
	// before the mark redelivers and re-enqueues idempotently — the
	// reverse order could lose the registration entirely.
	if err := s.enqueueAppRegistration(ctx, inst.ClusterID, inst.ID, target,
		RepoPath(inst.ClusterID, inst.CatalogItemID, inst.ID), inst.ResourceRef.Namespace); err != nil {
		return false, err
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if _, err := s.instances.MarkInstancePRMerged(ctx, tx, orgID, inst.ID, mergeSHA); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: "system:git-webhook", Impersonator: impersonation.FromContext(ctx),
			Action: "deploy.pr_merged", ObjectType: "resource_instance", ObjectID: inst.ID,
			Payload: json.RawMessage(fmt.Sprintf(`{"prUrl":%q,"mergeSha":%q}`, prURL, mergeSHA)),
		})
	})
	if err != nil {
		return false, fmt.Errorf("orchestrator: finalize PR merge: %w", err)
	}
	return true, nil
}

// ErrSameVersion rejects a rollback to the version the instance already runs.
var ErrSameVersion = fmt.Errorf("orchestrator: target version is the current version")

// ErrRepoMismatch rejects an explicit repoId that disagrees with the
// instance's recorded repo (repo is immutable across mutations; moving an
// instance between repos is a delete+redeploy).
var ErrRepoMismatch = fmt.Errorf("orchestrator: repoId does not match the instance's recorded repo")

// checkRepoSelector enforces the repo-immutability rule on instance
// mutations: an explicit selector must equal the recorded repo. The
// "default" sentinel matches when the recorded repo IS the org's current
// default; a legacy row (no recorded repo) accepts any selector that
// resolves to the current default (its manifests live there by
// definition). Any other disagreement is ErrRepoMismatch.
func (s *Service) checkRepoSelector(ctx context.Context, existing *types.ResourceInstance, selector string) error {
	if selector == "" || selector == existing.RepoID {
		return nil
	}
	if s.gitRepos == nil {
		// Legacy single-repo wiring: no registry to resolve against; only
		// the empty/default selectors are meaningful.
		if existing.RepoID == "" && selector == gitprovider.RepoSelectorDefault {
			return nil
		}
		return ErrRepoMismatch
	}
	if selector == gitprovider.RepoSelectorDefault && existing.RepoID == "" {
		return nil
	}
	// Resolve the caller's selector and the instance's effective repo
	// (recorded, else the default) and compare row IDs.
	want, _, _, err := s.gitRepos.ResolveRepo(ctx, existing.OrgID, selector)
	if err != nil {
		// Unknown selector: the deploy path 404s at enforcement; here it
		// reads as a mismatch.
		return ErrRepoMismatch
	}
	effective := existing.RepoID
	if effective == "" {
		def, _, _, derr := s.gitRepos.ResolveRepo(ctx, existing.OrgID, gitprovider.RepoSelectorDefault)
		if derr != nil {
			return derr
		}
		effective = def.ID
	}
	if want.ID == effective {
		return nil
	}
	return ErrRepoMismatch
}

// Gate actions for instance mutations that must not resume as deploys
// (ResumeHandler dispatches on these).
const (
	GateActionInstanceUpdate = "instance.update"
	GateActionInstanceDelete = "instance.delete"
)

// Upgrade re-deploys an existing instance at a newer version through the
// same path (§5.11 resource upgrade flow). repoID is the optional explicit
// selector: when non-empty it must match the instance's recorded repo.
func (s *Service) Upgrade(ctx context.Context, orgID, instanceID, toVersion, repoID, requester string) (*DeployResult, error) {
	return s.revert(ctx, orgID, instanceID, toVersion, repoID, requester, "")
}

// Rollback re-deploys an existing instance at an explicit (older) catalog
// version. There is no version history yet, so the target version is
// caller-supplied; the mechanics are the upgrade path with a distinct
// outbox event.
func (s *Service) Rollback(ctx context.Context, orgID, instanceID, toVersion, repoID, requester string) (*DeployResult, error) {
	existing, err := s.instances.Get(ctx, s.db.Pool, instanceID)
	if err != nil {
		return nil, err
	}
	if existing.OrgID != orgID {
		return nil, inventory.ErrInstanceNotFound
	}
	if existing.Version == toVersion {
		return nil, ErrSameVersion
	}
	return s.revert(ctx, orgID, instanceID, toVersion, repoID, requester, types.EventInstanceRolledBack)
}

// revert is the shared upgrade/rollback path; eventType overrides the
// outbox event emitted by apply (empty = instance.upgraded).
func (s *Service) revert(ctx context.Context, orgID, instanceID, toVersion, repoID, requester, eventType string) (*DeployResult, error) {
	existing, err := s.instances.Get(ctx, s.db.Pool, instanceID)
	if err != nil {
		return nil, err
	}
	if existing.OrgID != orgID {
		return nil, inventory.ErrInstanceNotFound
	}
	if err := s.checkRepoSelector(ctx, existing, repoID); err != nil {
		return nil, err
	}
	cluster, err := s.clusters.GetCluster(ctx, existing.ClusterID)
	if err != nil {
		return nil, err
	}
	if cluster.State != types.ClusterStateActive && cluster.State != types.ClusterStateDegraded {
		return nil, ErrClusterNotActive
	}
	item, err := s.catalog.GetItemByID(ctx, existing.CatalogItemID)
	if err != nil {
		return nil, err
	}
	if err := s.preFlight(ctx, PolicyInput{
		OrgID: orgID, ItemID: existing.CatalogItemID, Version: toVersion,
		ClusterID: existing.ClusterID, Spec: existing.Spec, Requester: requester,
		ClusterLabels: cluster.Labels, ClusterDistribution: cluster.Distribution,
	}); err != nil {
		return nil, err
	}
	gate, err := s.gate.Gate(ctx, approvals.GateInput{
		OrgID: orgID, Item: item, Version: toVersion, ClusterID: existing.ClusterID,
		Spec: existing.Spec, Requester: requester, OwnerTeam: existing.OwnerTeam,
		InstanceID: instanceID, RepoID: existing.RepoID,
	})
	if err != nil {
		return nil, err
	}
	if !gate.Approved {
		return &DeployResult{Status: "pending_approval", ApprovalID: gate.ApprovalID, Version: toVersion}, nil
	}
	return s.applyWithEvent(ctx, DeployRequest{
		OrgID: orgID, ClusterID: existing.ClusterID, ItemID: existing.CatalogItemID,
		Version: toVersion, OwnerTeam: existing.OwnerTeam, Spec: existing.Spec, Requester: requester,
	}, item, toVersion, existing, eventType, false)
}

// UpdateSpec re-renders an instance at its current version with a new spec
// (edit-spec flow). Approval-gated like upgrades; the gated request carries
// GateActionInstanceUpdate so the resume handler re-enters updateSpecResume
// instead of the deploy path.
func (s *Service) UpdateSpec(ctx context.Context, orgID, instanceID string, spec json.RawMessage, repoID, requester string) (*DeployResult, error) {
	existing, err := s.instances.Get(ctx, s.db.Pool, instanceID)
	if err != nil {
		return nil, err
	}
	if existing.OrgID != orgID {
		return nil, inventory.ErrInstanceNotFound
	}
	if err := s.checkRepoSelector(ctx, existing, repoID); err != nil {
		return nil, err
	}
	cluster, err := s.clusters.GetCluster(ctx, existing.ClusterID)
	if err != nil {
		return nil, err
	}
	if cluster.State != types.ClusterStateActive && cluster.State != types.ClusterStateDegraded {
		return nil, ErrClusterNotActive
	}
	item, err := s.catalog.GetItemByID(ctx, existing.CatalogItemID)
	if err != nil {
		return nil, err
	}
	if err := s.preFlight(ctx, PolicyInput{
		OrgID: orgID, ItemID: existing.CatalogItemID, Version: existing.Version,
		ClusterID: existing.ClusterID, Spec: spec, Requester: requester,
		ClusterLabels: cluster.Labels, ClusterDistribution: cluster.Distribution,
	}); err != nil {
		return nil, err
	}
	gate, err := s.gate.Gate(ctx, approvals.GateInput{
		OrgID: orgID, Item: item, Version: existing.Version, ClusterID: existing.ClusterID,
		Spec: spec, Requester: requester, OwnerTeam: existing.OwnerTeam,
		InstanceID: instanceID, Action: GateActionInstanceUpdate, RepoID: existing.RepoID,
	})
	if err != nil {
		return nil, err
	}
	if !gate.Approved {
		return &DeployResult{Status: "pending_approval", ApprovalID: gate.ApprovalID, Version: existing.Version}, nil
	}
	return s.applyWithEvent(ctx, DeployRequest{
		OrgID: orgID, ClusterID: existing.ClusterID, ItemID: existing.CatalogItemID,
		Version: existing.Version, OwnerTeam: existing.OwnerTeam, Spec: spec, Requester: requester,
	}, item, existing.Version, existing, types.EventInstanceUpdated, true)
}

// UpdateSpecResume re-enters the spec update after its approval was granted
// (ResumeHandler; the gate already ran at request time).
func (s *Service) UpdateSpecResume(ctx context.Context, orgID, instanceID string, spec json.RawMessage, requester string) error {
	existing, err := s.instances.Get(ctx, s.db.Pool, instanceID)
	if err != nil {
		return err
	}
	if existing.OrgID != orgID {
		return inventory.ErrInstanceNotFound
	}
	item, err := s.catalog.GetItemByID(ctx, existing.CatalogItemID)
	if err != nil {
		return err
	}
	_, err = s.applyWithEvent(ctx, DeployRequest{
		OrgID: orgID, ClusterID: existing.ClusterID, ItemID: existing.CatalogItemID,
		Version: existing.Version, OwnerTeam: existing.OwnerTeam, Spec: spec, Requester: requester,
	}, item, existing.Version, existing, types.EventInstanceUpdated, true)
	return err
}

// DeleteInstance undeploys an instance. Approval-gated like deploys; the
// gated request carries GateActionInstanceDelete so the resume handler
// re-enters DeleteInstanceResume instead of the deploy path.
func (s *Service) DeleteInstance(ctx context.Context, orgID, instanceID, requester string) (*DeployResult, error) {
	existing, err := s.instances.Get(ctx, s.db.Pool, instanceID)
	if err != nil {
		return nil, err
	}
	if existing.OrgID != orgID {
		return nil, inventory.ErrInstanceNotFound
	}
	item, err := s.catalog.GetItemByID(ctx, existing.CatalogItemID)
	if err != nil {
		return nil, err
	}
	gate, err := s.gate.Gate(ctx, approvals.GateInput{
		OrgID: orgID, Item: item, Version: existing.Version, ClusterID: existing.ClusterID,
		Spec: existing.Spec, Requester: requester, OwnerTeam: existing.OwnerTeam,
		InstanceID: instanceID, Action: GateActionInstanceDelete,
	})
	if err != nil {
		return nil, err
	}
	if !gate.Approved {
		return &DeployResult{Status: "pending_approval", ApprovalID: gate.ApprovalID, Version: existing.Version}, nil
	}
	if err := s.deleteInstance(ctx, existing, requester); err != nil {
		return nil, err
	}
	return &DeployResult{InstanceID: instanceID, Version: existing.Version, Status: string(types.InstanceStateDeleting)}, nil
}

// DeleteInstanceResume re-enters the delete after its approval was granted
// (ResumeHandler; the gate already ran at request time).
func (s *Service) DeleteInstanceResume(ctx context.Context, orgID, instanceID, requester string) error {
	existing, err := s.instances.Get(ctx, s.db.Pool, instanceID)
	if err != nil {
		return err
	}
	if existing.OrgID != orgID {
		return inventory.ErrInstanceNotFound
	}
	return s.deleteInstance(ctx, existing, requester)
}

// deleteInstance removes the instance's desired state from the repo it was
// recorded against (Feature A; legacy rows fall back to the org default),
// asks the agent to remove the ArgoCD app (best-effort), and deletes the
// inventory row with audit + outbox in one TX.
func (s *Service) deleteInstance(ctx context.Context, existing *types.ResourceInstance, requester string) error {
	orgID, instanceID := existing.OrgID, existing.ID
	target, err := s.resolveTarget(ctx, orgID, existing.RepoID)
	if err != nil {
		return err
	}
	git := target.provider
	if target.ensureRepo {
		if _, err := git.EnsureRepo(ctx, target.repo); err != nil {
			return err
		}
	}
	path := RepoPath(existing.ClusterID, existing.CatalogItemID, instanceID)
	message := fmt.Sprintf("undeploy %s from %s (instance %s)", existing.CatalogItemID, existing.ClusterID, instanceID)
	// NOTE: DeleteFiles commits directly even for pull-request-policy
	// tenants (no PR-delete path in the provider yet).
	if _, err := git.DeleteFiles(ctx, target.repo, target.branch,
		[]string{path + "/instance.yaml", path + "/application.yaml"}, message); err != nil {
		return fmt.Errorf("orchestrator: git delete: %w", err)
	}
	// Best-effort agent cleanup: ask the tenant-local ArgoCD to delete the
	// app. A failure here must not block the undeploy — the git delete
	// already stops reconciliation of the kro CR source.
	_ = s.enqueueAppDeletion(ctx, existing.ClusterID, instanceID)

	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.instances.Delete(ctx, tx, instanceID); err != nil {
			return err
		}
		ev := &types.AuditEvent{
			OrgID: orgID, Actor: requester, Impersonator: impersonation.FromContext(ctx), Action: "instance.deleted",
			ObjectType: "resource_instance", ObjectID: instanceID,
			Payload: json.RawMessage(fmt.Sprintf(`{"item":%q,"version":%q,"cluster":%q}`,
				existing.CatalogItemID, existing.Version, existing.ClusterID)),
		}
		if err := impersonation.Stamp(ctx, ev); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, ev); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventInstanceDeleted, types.InstancePayload{
			OrgID: orgID, InstanceID: instanceID, ItemID: existing.CatalogItemID,
			ClusterID: existing.ClusterID, Version: existing.Version,
		})
	})
}

// enqueueAppDeletion dispatches an InvokeAction (delete) for the instance's
// ArgoCD Application to the cluster's agent.
func (s *Service) enqueueAppDeletion(ctx context.Context, clusterID, instanceID string) error {
	cmd := &agentv1.InvokeAction{
		CommandId: instanceID,
		Action:    "delete",
		Resource: &agentv1.ResourceRef{
			Kind:      "Application",
			Name:      "inari-" + strings.ToLower(instanceID),
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
		ID:        "delete-argocd-app:" + instanceID,
		ClusterID: clusterID,
		Type:      agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_INVOKE_ACTION),
		Payload:   raw,
	})
}

// DiffPreview returns the data the console needs to render an upgrade diff:
// current vs target rendered manifests plus the spec delta.
func (s *Service) DiffPreview(ctx context.Context, orgID, instanceID, toVersion string) (*DiffPreview, error) {
	existing, err := s.instances.Get(ctx, s.db.Pool, instanceID)
	if err != nil {
		return nil, err
	}
	if existing.OrgID != orgID {
		return nil, inventory.ErrInstanceNotFound
	}
	cur, err := s.catalog.GetVersion(ctx, existing.CatalogItemID, existing.Version)
	if err != nil {
		return nil, err
	}
	next, err := s.catalog.GetVersion(ctx, existing.CatalogItemID, toVersion)
	if err != nil {
		return nil, err
	}
	name := existing.ResourceRef.Name
	namespace := existing.ResourceRef.Namespace
	curManifest, err := RenderInstanceManifest(cur, name, namespace, existing.Spec)
	if err != nil {
		return nil, err
	}
	nextManifest, err := RenderInstanceManifest(next, name, namespace, existing.Spec)
	if err != nil {
		return nil, err
	}
	return &DiffPreview{
		InstanceID:      instanceID,
		ItemID:          existing.CatalogItemID,
		CurrentVersion:  existing.Version,
		TargetVersion:   toVersion,
		CurrentManifest: string(curManifest),
		TargetManifest:  string(nextManifest),
		CurrentSchema:   cur.Schema,
		TargetSchema:    next.Schema,
	}, nil
}

// DiffPreview is the console's upgrade diff data (§5.11).
type DiffPreview struct {
	InstanceID      string          `json:"instanceId"`
	ItemID          string          `json:"itemId"`
	CurrentVersion  string          `json:"currentVersion"`
	TargetVersion   string          `json:"targetVersion"`
	CurrentManifest string          `json:"currentManifest"`
	TargetManifest  string          `json:"targetManifest"`
	CurrentSchema   json.RawMessage `json:"currentSchema,omitempty"`
	TargetSchema    json.RawMessage `json:"targetSchema,omitempty"`
}

// SetGitConfig configures the tenant's state repo (admin flow; the tenant
// zone factory will own this later).
func (s *Service) SetGitConfig(ctx context.Context, actor string, cfg *types.TenantGitConfig) error {
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.instances.UpsertGitConfig(ctx, tx, cfg); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: cfg.OrgID, Actor: actor, Action: "git.config_set",
			ObjectType: "tenant", ObjectID: cfg.OrgID,
			Payload: json.RawMessage(fmt.Sprintf(`{"repo":%q,"commitPolicy":%q,"byoGitApp":%t,"userTemplateFallback":%q}`, cfg.Repo, cfg.CommitPolicy, cfg.GitHubApp != nil, cfg.UserTemplateFallback)),
		})
	})
	if err != nil {
		return err
	}
	// Drop cached credentials so the next deploy picks up the new config
	// (no-op for static resolvers).
	if ev, ok := s.git.(interface{ EvictTenant(string) }); ok {
		ev.EvictTenant(cfg.OrgID)
	}
	return nil
}

// GitProviderStatus health-checks the tenant's git provider auth (cached).
func (s *Service) GitProviderStatus(ctx context.Context, orgID string) (*types.GitProviderStatus, error) {
	cfg, err := s.instances.GitConfig(ctx, s.db.Pool, orgID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, ErrNoGitConfig
	}
	prober, ok := s.git.(interface {
		Probe(context.Context, *types.TenantGitConfig) *types.GitProviderStatus
	})
	if !ok {
		return &types.GitProviderStatus{State: "unknown", AuthModel: "static"}, nil
	}
	return prober.Probe(ctx, cfg), nil
}

// GetGitConfig reads the tenant's git config.
func (s *Service) GetGitConfig(ctx context.Context, orgID string) (*types.TenantGitConfig, error) {
	return s.instances.GitConfig(ctx, s.db.Pool, orgID)
}

// RepoURL normalizes an owner/name slug into a canonical https clone URL
// (GitHub casing rules: scheme+host+org lowercased for ArgoCD repo-creds
// prefix matching). Exported for the gitrepos root-app attach render.
func RepoURL(repo string) string {
	u := repo
	if len(u) > 8 && u[:8] == "https://" {
	} else {
		u = "https://github.com/" + u
	}
	// GitHub is case-insensitive but ArgoCD repo-creds prefix matching is
	// not: normalize scheme+host+org to lowercase so credentials configured
	// for the canonical org casing apply (7K-Group == 7k-group upstream).
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			host := rest[:j]
			path := rest[j+1:]
			if k := strings.Index(path, "/"); k >= 0 {
				return strings.ToLower(u[:i+3]+host) + "/" + strings.ToLower(path[:k]) + path[k:]
			}
			return strings.ToLower(u[:i+3]+host) + "/" + strings.ToLower(path)
		}
	}
	return u
}

func kindOf(manifest []byte) string {
	var doc struct {
		Kind string `yaml:"kind"`
	}
	if err := yaml.Unmarshal(manifest, &doc); err != nil {
		return ""
	}
	return doc.Kind
}
