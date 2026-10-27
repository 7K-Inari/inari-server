// Package addons implements first-class cluster addons (Feature C, parent
// plan §6): discovery ingest from the agent scanner, adoption into GitOps
// (render via internal/renderer → commit per repo policy → register the
// ArgoCD Application/ApplicationSet via the agent), and the CD update loop
// (version/values edits committed back to git). Adoption registers with
// prune OFF + take-ownership (decision 2); prune is flipped only by the
// explicit, audit-logged enable-prune action.
//
// Fleet membership for ApplicationSet addons is computed server-side from
// inventory cluster labels (decision 8) — never from ArgoCD cluster-secret
// labels — and cluster register/delete events re-render affected
// ApplicationSets via the outbox consumer (FleetReconciler).
package addons

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/impersonation"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/renderer"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TakeOwnershipSyncOption is set on adoption renders so ArgoCD adopts the
// existing (discovered) resources in place instead of conflicting on them
// (decision 2).
const TakeOwnershipSyncOption = "TakeOwnership=true"

// RegisterAppSetEventType is the agent command type for ApplicationSet
// registration. The pinned agent contract has no RegisterArgoCDAppSet
// message yet (proto mod lands with the agent milestone); until then the
// command payload is a structpb.Struct bridge — see enqueueRegistration.
const RegisterAppSetEventType = "EVENT_TYPE_REGISTER_ARGOCD_APPSET"

// Sentinel errors mapped to HTTP statuses by the handler.
var (
	// ErrAlreadyManaged rejects adopting an addon that is already managed.
	ErrAlreadyManaged = errors.New("addons: addon is already managed")
	// ErrNotManaged rejects updates/prune on rows that are not managed yet.
	ErrNotManaged = errors.New("addons: addon is not managed")
	// ErrNoRepoConfig mirrors the orchestrator's no-git-config conflict: the
	// org has no resolvable repo to commit addon manifests to.
	ErrNoRepoConfig = errors.New("addons: tenant has no git repo configured")
	// ErrNotDeployable rejects adopt on catalog versions without an
	// addon-deployable payload (no chart and no rgd).
	ErrNotDeployable = errors.New("addons: catalog item version has no addon-deployable payload")
	// ErrEmptyFleet rejects applicationset deploys whose cluster selector
	// matches no active registered cluster.
	ErrEmptyFleet = errors.New("addons: cluster selector matches no registered cluster")
	// ErrPruneAlreadyEnabled makes enable-prune idempotent-as-conflict.
	ErrPruneAlreadyEnabled = errors.New("addons: prune is already enabled")
	// ErrInvalidDeployMode rejects unknown deploy modes.
	ErrInvalidDeployMode = errors.New("addons: deployMode must be application or applicationset")
)

// FieldError is one values-schema validation failure (422 detail).
type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// ValidationError carries field-level schema violations (decision 4: hard
// 422 on invalid values; no schema = allow).
type ValidationError struct {
	Fields []FieldError
}

func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		parts = append(parts, fmt.Sprintf("%s: %s", f.Path, f.Message))
	}
	return "addons: values failed schema validation: " + strings.Join(parts, "; ")
}

// Store is the inventory seam the service needs.
type Store interface {
	GetClusterAddon(ctx context.Context, q db.Querier, orgID, clusterID, catalogItem string) (*types.ClusterAddon, error)
	GetClusterAddonByID(ctx context.Context, q db.Querier, orgID, id string) (*types.ClusterAddon, error)
	ListClusterAddons(ctx context.Context, q db.Querier, orgID, clusterID string) ([]*types.ClusterAddon, error)
	UpsertClusterAddon(ctx context.Context, q db.Querier, a *types.ClusterAddon) error
	UpsertDiscoveredAddon(ctx context.Context, q db.Querier, a *types.ClusterAddon) error
	// ClaimClusterAddonForAdoption atomically claims the (cluster, item)
	// slot for adopt (concurrent adopts: exactly one winner); a claimed
	// discovered row keeps its ID. ok=false maps to ErrAlreadyManaged.
	ClaimClusterAddonForAdoption(ctx context.Context, q db.Querier, a *types.ClusterAddon) (id string, meta json.RawMessage, inserted, ok bool, err error)
	// ReleaseClusterAddonClaim rolls back a failed adopt's claim.
	ReleaseClusterAddonClaim(ctx context.Context, q db.Querier, orgID, id string, inserted bool) error
	// AbsorbDiscoveredAddons deletes one catalog item's per-cluster
	// state=discovered rows (fleet adoption supersedes them) and returns
	// their sightings for merging into the fleet row's discovered_meta.
	AbsorbDiscoveredAddons(ctx context.Context, q db.Querier, orgID, catalogItem string) ([]json.RawMessage, error)
	// BaselineRepoSelector resolves the repo an adopt defaults to for one
	// cluster (bound baseline, else org default; "" = none registered).
	BaselineRepoSelector(ctx context.Context, q db.Querier, orgID, clusterID string) (string, error)
	// SetClusterAddonState forces the lifecycle state (update_failed flip).
	SetClusterAddonState(ctx context.Context, q db.Querier, orgID, id string, state types.AddonState) error
	// GetGitRepo feeds team filtering on list responses.
	GetGitRepo(ctx context.Context, q db.Querier, orgID, id string) (*types.TenantGitRepo, error)
}

// CatalogResolver is the catalog seam: item lookup, version resolution for
// the dropdown/adopt/update, and version listing.
type CatalogResolver interface {
	GetItemByID(ctx context.Context, itemID string) (*types.CatalogItem, error)
	GetVersion(ctx context.Context, itemID, version string) (*types.CatalogItemVersion, error)
	ListVersions(ctx context.Context, itemID string) ([]types.CatalogItemVersion, error)
	// EffectiveVersion resolves the deploy default (pin/latest in channel).
	EffectiveVersion(ctx context.Context, orgID, itemID, channel string) (string, error)
}

// ClusterLister is the cluster registry seam.
type ClusterLister interface {
	GetCluster(ctx context.Context, id string) (*types.Cluster, error)
	ListClusters(ctx context.Context, orgID string) ([]types.Cluster, error)
}

// Queue is the agent command queue seam (agentgateway.Queue).
type Queue interface {
	Enqueue(ctx context.Context, cmd *types.AgentCommand) error
}

// Service is the addons module.
type Service struct {
	db       *db.DB
	store    Store
	catalog  CatalogResolver
	clusters ClusterLister
	git      *gitprovider.RepoResolver
	renders  *renderer.Registry
	queue    Queue
	audit    *audit.Store
}

// NewService wires the module. queue may be nil (registration commands are
// then skipped); audit may be nil (audit/outbox writes skipped).
func NewService(d *db.DB, store Store, catalog CatalogResolver, clusters ClusterLister,
	git *gitprovider.RepoResolver, queue Queue, auditStore *audit.Store) *Service {
	s := &Service{
		db: d, store: store, catalog: catalog, clusters: clusters,
		git: git, queue: queue, audit: auditStore,
	}
	s.renders = renderer.New(s.resolveRGD)
	return s
}

// resolveRGD resolves kro source descriptor refs ("<itemID>@<version>")
// against the catalog version payload — the same convention the
// orchestrator's renderer wiring uses.
func (s *Service) resolveRGD(ctx context.Context, ref string) ([]byte, error) {
	itemID, version, ok := strings.Cut(ref, "@")
	if !ok || itemID == "" || version == "" {
		return nil, fmt.Errorf("addons: malformed RGD ref %q (want <itemID>@<version>)", ref)
	}
	ver, err := s.catalog.GetVersion(ctx, itemID, version)
	if err != nil {
		return nil, fmt.Errorf("addons: resolve RGD %q: %w", ref, err)
	}
	var payload struct {
		RGD string `json:"rgd"`
	}
	if err := json.Unmarshal(ver.Payload, &payload); err != nil {
		return nil, fmt.Errorf("addons: parse version payload: %w", err)
	}
	if payload.RGD == "" {
		return nil, fmt.Errorf("addons: catalog version %s has no rgd payload", ref)
	}
	return []byte(payload.RGD), nil
}

// versionPayload is the catalog version payload shape the addons module
// understands (ocisync conventions): platform-app packages carry "chart",
// kro packages carry "rgd".
type versionPayload struct {
	Chart *struct {
		RepoURL   string `json:"repoURL"`
		Chart     string `json:"chart"`
		Namespace string `json:"namespace"`
	} `json:"chart"`
	RGD string `json:"rgd"`
}

// descriptorFor builds the source descriptor for a catalog item version:
// chart payload → helm source (chart version = the catalog version string,
// per the platform-app channel mapping); rgd payload → kro source.
func descriptorFor(itemID string, ver *types.CatalogItemVersion) (types.SourceDescriptor, *versionPayload, error) {
	var p versionPayload
	if len(ver.Payload) > 0 {
		if err := json.Unmarshal(ver.Payload, &p); err != nil {
			return types.SourceDescriptor{}, nil, fmt.Errorf("addons: parse version payload: %w", err)
		}
	}
	switch {
	case p.Chart != nil && p.Chart.RepoURL != "" && p.Chart.Chart != "":
		return types.SourceDescriptor{
			Kind: types.SourceKindHelm,
			Helm: &types.HelmSource{RepoURL: p.Chart.RepoURL, Chart: p.Chart.Chart, Version: ver.Version},
		}, &p, nil
	case p.RGD != "":
		return types.SourceDescriptor{
			Kind: types.SourceKindKRO,
			KRO:  &types.KROSource{RGDRef: itemID + "@" + ver.Version},
		}, &p, nil
	default:
		return types.SourceDescriptor{}, nil, ErrNotDeployable
	}
}

// validateValues enforces decision 4: when the catalog version ships a
// values schema (platform-app packages vendor the upstream chart's
// values.schema.json into the version's schema field), values must
// validate — hard 422 with field-level errors. No schema = allow (lenient
// fallback for community items), but the OBJECT-shape requirement applies
// regardless: scalar/array values can never be helm values or a kro
// instance spec and would otherwise fail as a 500 deep in the renderer.
func validateValues(schemaRaw, values json.RawMessage) error {
	var v any
	if len(values) > 0 {
		dec := json.NewDecoder(bytes.NewReader(values))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return &ValidationError{Fields: []FieldError{{Path: "", Message: "values is not valid JSON"}}}
		}
	}
	if v == nil {
		v = map[string]any{}
	} else if _, ok := v.(map[string]any); !ok {
		return &ValidationError{Fields: []FieldError{{Path: "", Message: "values must be a JSON object"}}}
	}
	if len(schemaRaw) == 0 {
		return nil
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		return fmt.Errorf("addons: parse values schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("values.schema.json", doc); err != nil {
		return fmt.Errorf("addons: load values schema: %w", err)
	}
	sch, err := compiler.Compile("values.schema.json")
	if err != nil {
		return fmt.Errorf("addons: compile values schema: %w", err)
	}
	verr := sch.Validate(v)
	var schemaErr *jsonschema.ValidationError
	if errors.As(verr, &schemaErr) {
		return &ValidationError{Fields: collectFieldErrors(schemaErr)}
	}
	return verr
}

// collectFieldErrors flattens the validation error tree into leaf
// instance-location/message pairs (same shape as scaffold's schema errors).
func collectFieldErrors(ve *jsonschema.ValidationError) []FieldError {
	if len(ve.Causes) == 0 {
		path := ""
		for _, seg := range ve.InstanceLocation {
			path += "/" + seg
		}
		return []FieldError{{Path: path, Message: ve.Error()}}
	}
	var out []FieldError
	for _, c := range ve.Causes {
		out = append(out, collectFieldErrors(c)...)
	}
	return out
}

// matchSelector evaluates a cluster selector server-side (decision 8):
// equality match on the cluster's Inari-side labels; an empty selector
// matches every cluster.
func matchSelector(selector, labels map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// resolveFleetTargets evaluates the selector over the org's active
// clusters, sorted for deterministic list-generator output. At least one
// match is required.
func (s *Service) resolveFleetTargets(ctx context.Context, orgID string, selector map[string]string) ([]renderer.ClusterTarget, error) {
	clusters, err := s.clusters.ListClusters(ctx, orgID)
	if err != nil {
		return nil, err
	}
	var out []renderer.ClusterTarget
	for _, c := range clusters {
		if c.State != types.ClusterStateActive && c.State != types.ClusterStateDegraded {
			continue
		}
		if matchSelector(selector, c.Labels) {
			out = append(out, renderer.ClusterTarget{ID: c.ID, Name: c.Name})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) == 0 {
		return nil, ErrEmptyFleet
	}
	return out, nil
}

// AddonView is the list-response row: the addon plus the catalog versions
// available for the version dropdown.
type AddonView struct {
	types.ClusterAddon
	AvailableVersions []string `json:"availableVersions,omitempty"`
}

// List returns the cluster's addons (discovered + managed), including
// managed fleet ('*') rows whose cluster selector matches this cluster's
// labels — the same server-side targeting semantics as the renderer
// (decision 8). teamIDs nil = privileged caller (see all); otherwise
// managed rows are visible only when the caller's teams own the row's repo
// (platform repos read-visible to all, decision 5), while discovered rows
// (no repo yet) are visible to every org member — they are plain cluster
// state.
func (s *Service) List(ctx context.Context, orgID, clusterID string, teamIDs []string) ([]AddonView, error) {
	rows, err := s.store.ListClusterAddons(ctx, s.querier(), orgID, clusterID)
	if err != nil {
		return nil, err
	}
	// Fleet rows are re-filtered against this cluster's labels; an
	// unresolvable cluster yields nil labels, so only selector-less fleet
	// rows (target: all clusters) match — consistent with matchSelector.
	var clusterLabels map[string]string
	if c, err := s.clusters.GetCluster(ctx, clusterID); err == nil {
		clusterLabels = c.Labels
	}
	repoCache := map[string]*types.TenantGitRepo{}
	visible := func(a *types.ClusterAddon) (bool, error) {
		if teamIDs == nil || a.RepoID == "" {
			return true, nil
		}
		row, ok := repoCache[a.RepoID]
		if !ok {
			r, err := s.store.GetGitRepo(ctx, s.querier(), orgID, a.RepoID)
			if errors.Is(err, inventory.ErrRepoNotFound) {
				// Orphaned reference (repo unregistered with mode=orphan):
				// fail closed for non-privileged callers.
				return false, nil
			}
			if err != nil {
				return false, err
			}
			repoCache[a.RepoID] = r
			row = r
		}
		if row.Scope == types.GitRepoScopePlatform {
			return true, nil
		}
		for _, t := range teamIDs {
			if t == row.TeamID {
				return true, nil
			}
		}
		return false, nil
	}
	items := map[string]bool{}
	var filtered []*types.ClusterAddon
	for _, a := range rows {
		if a.ClusterID == "*" && !matchSelector(a.ClusterSelector, clusterLabels) {
			continue // fleet addon not targeting this cluster
		}
		ok, err := visible(a)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		filtered = append(filtered, a)
		items[a.CatalogItem] = true
	}
	versions := map[string][]string{}
	for id := range items {
		vers, err := s.catalog.ListVersions(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, v := range vers {
			versions[id] = append(versions[id], v.Version)
		}
	}
	out := make([]AddonView, 0, len(filtered))
	for _, a := range filtered {
		out = append(out, AddonView{ClusterAddon: *a, AvailableVersions: versions[a.CatalogItem]})
	}
	return out, nil
}

// Get returns one addon by ID, scoped to the org (the handler's
// recorded-repo enforcement seam).
func (s *Service) Get(ctx context.Context, orgID, id string) (*types.ClusterAddon, error) {
	return s.store.GetClusterAddonByID(ctx, s.querier(), orgID, id)
}

// AdoptInput is one adopt request (POST .../addons/{catalogItem}/adopt).
type AdoptInput struct {
	// RepoID selects the target repo; empty = the cluster's bound baseline
	// (falling back to the org default).
	RepoID string
	// Version is the catalog version (= chart version for platform apps);
	// empty resolves the effective (pinned/latest stable) version.
	Version string
	// Values is the helm values / kro instance spec object.
	Values json.RawMessage
	// DeployMode selects application (single cluster) vs applicationset
	// (fleet-wide); default application.
	DeployMode types.AddonDeployMode
	// ClusterSelector is the fleet label query (applicationset mode only);
	// empty selects all of the org's clusters.
	ClusterSelector map[string]string
	// Namespace overrides the destination namespace; empty = the chart's
	// declared namespace, else the item name.
	Namespace string
}

// AdoptResult reports the outcome of adopt/update/enable-prune.
type AdoptResult struct {
	Addon     *types.ClusterAddon
	CommitSHA string
	PRURL     string
}

// Adopt brings a (discovered or declared) addon under GitOps management:
// validate values → render → commit per repo policy → register the ArgoCD
// app(/set) with prune OFF + take-ownership → record state=managed. A
// pre-existing discovered row keeps its ID so status folding and UI deep
// links stay stable across adoption.
func (s *Service) Adopt(ctx context.Context, orgID, clusterID, catalogItem string, in AdoptInput, actor string) (*AdoptResult, error) {
	cluster, err := s.clusters.GetCluster(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	if cluster.OrgID != orgID {
		return nil, orchestrator.ErrClusterMismatch
	}
	// The item must exist; its name seeds the workload/repo-path defaults.
	if _, err := s.catalog.GetItemByID(ctx, catalogItem); err != nil {
		return nil, err
	}
	mode := in.DeployMode
	if mode == "" {
		mode = types.AddonDeployModeApplication
	}
	if mode != types.AddonDeployModeApplication && mode != types.AddonDeployModeApplicationSet {
		return nil, ErrInvalidDeployMode
	}

	// Fleet rows key on cluster '*'; single-cluster rows on the cluster.
	rowCluster := clusterID
	if mode == types.AddonDeployModeApplicationSet {
		rowCluster = "*"
	}

	version := in.Version
	if version == "" {
		if version, err = s.catalog.EffectiveVersion(ctx, orgID, catalogItem, "stable"); err != nil {
			return nil, err
		}
	}
	ver, err := s.catalog.GetVersion(ctx, catalogItem, version)
	if err != nil {
		return nil, err
	}
	desc, payload, err := descriptorFor(catalogItem, ver)
	if err != nil {
		return nil, err
	}
	if err := validateValues(ver.Schema, in.Values); err != nil {
		return nil, err
	}

	selector := in.RepoID
	if selector == "" {
		if selector, err = s.store.BaselineRepoSelector(ctx, s.querier(), orgID, clusterID); err != nil {
			return nil, err
		}
	}
	repo, provider, authInfo, err := s.resolveRepo(ctx, orgID, selector)
	if err != nil {
		return nil, err
	}

	namespace := in.Namespace
	if namespace == "" && payload.Chart != nil {
		namespace = payload.Chart.Namespace
	}
	if namespace == "" {
		namespace = workloadName(catalogItem)
	}
	targets, err := s.resolveTargets(ctx, orgID, cluster, mode, in.ClusterSelector)
	if err != nil {
		return nil, err
	}

	// Claim the (cluster, item) slot atomically BEFORE any side effects:
	// concurrent adopts race here, and exactly one wins (the others get
	// ErrAlreadyManaged). A pre-existing discovered row keeps its ID so
	// status folding and UI deep links stay stable across adoption.
	provisionalID := ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
	var addonID string
	var discoveredMeta json.RawMessage
	var inserted, claimed bool
	err = s.inTx(ctx, func(q db.Querier) error {
		var err error
		addonID, discoveredMeta, inserted, claimed, err = s.store.ClaimClusterAddonForAdoption(ctx, q, &types.ClusterAddon{
			ID: provisionalID, OrgID: orgID, ClusterID: rowCluster, CatalogItem: catalogItem,
			DeployMode: mode, Source: desc,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	if !claimed {
		return nil, ErrAlreadyManaged
	}
	// From here on, failures must release the claim so a failed adopt is
	// retryable (a stranded adopting row also becomes reclaimable after
	// the store's staleness window).
	release := func() {
		if err := s.inTx(ctx, func(q db.Querier) error {
			return s.store.ReleaseClusterAddonClaim(ctx, q, orgID, addonID, inserted)
		}); err != nil {
			slog.Warn("addons: release adopt claim", "addon", addonID, "error", err)
		}
	}

	repoPath := "addons/" + workloadName(catalogItem)
	files, err := s.render(ctx, desc, renderParams{
		addonID: addonID, name: workloadName(catalogItem), namespace: namespace,
		mode: mode, targets: targets, prune: false,
		values: in.Values, repo: repo, path: repoPath,
	})
	if err != nil {
		release()
		return nil, err
	}
	message := fmt.Sprintf("adopt addon %s@%s on %s (addon %s)", catalogItem, version, rowCluster, addonID)
	gitResult, err := commitPerPolicy(ctx, provider, repo, message, files)
	if err != nil {
		release()
		return nil, fmt.Errorf("addons: git write: %w", err)
	}

	// PR-policy writes register with ArgoCD after the merge (same
	// documented webhook gap as instance deploys).
	if gitResult.PRURL == "" {
		if err := s.enqueueRegistration(ctx, clusterID, addonID, mode, desc, repo, repoPath, namespace, false, files); err != nil {
			release()
			return nil, err
		}
	}

	row := &types.ClusterAddon{
		ID: addonID, OrgID: orgID, ClusterID: rowCluster, CatalogItem: catalogItem,
		State: types.AddonStateManaged, DeployMode: mode,
		RepoID: repo.ID, RepoPath: repoPath, Source: desc, ChartVersion: version,
		Values: in.Values, ArgoCDApp: appName(addonID, mode), Namespace: namespace,
		CommitSHA: gitResult.CommitSHA, PRURL: gitResult.PRURL,
		ClusterSelector: in.ClusterSelector, DiscoveredMeta: discoveredMeta,
	}
	err = s.inTx(ctx, func(q db.Querier) error {
		// Fleet adoption supersedes every per-cluster discovered row for
		// the item (decision: single source of truth); the scan evidence
		// moves into the fleet row's discovered_meta as sightings.
		absorbed := 0
		if mode == types.AddonDeployModeApplicationSet {
			sightings, err := s.store.AbsorbDiscoveredAddons(ctx, q, orgID, catalogItem)
			if err != nil {
				return err
			}
			absorbed = len(sightings)
			if absorbed > 0 {
				meta, err := json.Marshal(map[string]any{"absorbedSightings": sightings})
				if err != nil {
					return err
				}
				row.DiscoveredMeta = meta
			}
		}
		if err := s.store.UpsertClusterAddon(ctx, q, row); err != nil {
			return err
		}
		if err := s.recordAudit(ctx, q, orgID, actor, "addon.adopted", row.ID, map[string]any{
			"catalogItem": catalogItem, "cluster": rowCluster, "version": version,
			"deployMode": string(mode), "repo": repo.Repo, "commitSha": gitResult.CommitSHA,
			"prUrl": gitResult.PRURL, "authModel": string(authInfo.Model),
			"absorbedDiscovered": absorbed,
		}); err != nil {
			return err
		}
		return s.appendOutbox(ctx, q, orgID, types.EventAddonAdopted, types.AddonPayload{
			OrgID: orgID, AddonID: row.ID, CatalogItem: catalogItem, ClusterID: rowCluster,
			Version: version, CommitSHA: gitResult.CommitSHA, PRURL: gitResult.PRURL, RepoID: repo.ID,
		})
	})
	if err != nil {
		release()
		return nil, fmt.Errorf("addons: record adopt: %w", err)
	}
	return &AdoptResult{Addon: row, CommitSHA: gitResult.CommitSHA, PRURL: gitResult.PRURL}, nil
}

// UpdateInput is a PATCH on a managed addon. Nil fields stay unchanged.
type UpdateInput struct {
	// ChartVersion moves to another catalog version (= chart version for
	// platform apps); stored values are re-validated against the new
	// version's schema before anything is committed (decision 4).
	ChartVersion *string
	// Values replaces the stored values object.
	Values *json.RawMessage
}

// Update re-renders a managed addon at a new version and/or with new
// values, commits per the repo's policy, and re-registers the ArgoCD
// app(/set). Git/render failures flip the row to update_failed.
func (s *Service) Update(ctx context.Context, orgID, addonID string, in UpdateInput, actor string) (*AdoptResult, error) {
	row, err := s.store.GetClusterAddonByID(ctx, s.querier(), orgID, addonID)
	if err != nil {
		return nil, err
	}
	if row.State != types.AddonStateManaged && row.State != types.AddonStateUpdateFailed {
		return nil, ErrNotManaged
	}
	version := row.ChartVersion
	if in.ChartVersion != nil {
		version = *in.ChartVersion
	}
	ver, err := s.catalog.GetVersion(ctx, row.CatalogItem, version)
	if err != nil {
		return nil, err
	}
	values := row.Values
	if in.Values != nil {
		values = *in.Values
	}
	// Re-validate against the (possibly new) version's schema (decision 4).
	if err := validateValues(ver.Schema, values); err != nil {
		return nil, err
	}
	// Re-derive the descriptor from the TARGET version's catalog payload
	// (chart coordinates/RGD ref may move between versions); the stored
	// source only carries the old version's coordinates.
	desc, _, err := descriptorFor(row.CatalogItem, ver)
	if err != nil {
		return nil, err
	}

	res, err := s.rerender(ctx, row, desc, version, values, row.PruneEnabled, actor, "update")
	if err != nil {
		s.markUpdateFailed(ctx, orgID, row)
		return nil, err
	}
	return res, nil
}

// EnablePrune is the explicit human action flipping an adopted addon to
// prune-on (decision 2): re-render with prune enabled, commit per policy,
// re-register, audit. One-directional; a second call is a conflict.
func (s *Service) EnablePrune(ctx context.Context, orgID, addonID, actor string) (*AdoptResult, error) {
	row, err := s.store.GetClusterAddonByID(ctx, s.querier(), orgID, addonID)
	if err != nil {
		return nil, err
	}
	if row.State != types.AddonStateManaged {
		return nil, ErrNotManaged
	}
	if row.PruneEnabled {
		return nil, ErrPruneAlreadyEnabled
	}
	return s.rerender(ctx, row, row.Source, row.ChartVersion, row.Values, true, actor, "enable-prune")
}

// rerender is the shared update/enable-prune machinery: resolve repo +
// targets from the stored row, render, commit per policy, re-register
// (direct policy only), persist, audit, outbox.
func (s *Service) rerender(ctx context.Context, row *types.ClusterAddon, desc types.SourceDescriptor,
	version string, values json.RawMessage, prune bool, actor, action string) (*AdoptResult, error) {
	repo, provider, authInfo, err := s.git.ResolveRepo(ctx, row.OrgID, row.RepoID)
	if err != nil {
		return nil, err
	}
	targets, err := s.targetsForRow(ctx, row)
	if err != nil {
		return nil, err
	}
	namespace := row.Namespace
	if namespace == "" {
		namespace = workloadName(row.CatalogItem)
	}
	files, err := s.render(ctx, desc, renderParams{
		addonID: row.ID, name: workloadName(row.CatalogItem), namespace: namespace,
		mode: row.DeployMode, targets: targets, prune: prune,
		values: values, repo: repo, path: row.RepoPath,
	})
	if err != nil {
		return nil, err
	}
	message := fmt.Sprintf("%s addon %s@%s (addon %s)", action, row.CatalogItem, version, row.ID)
	gitResult, err := commitPerPolicy(ctx, provider, repo, message, files)
	if err != nil {
		return nil, fmt.Errorf("addons: git write: %w", err)
	}
	if gitResult.PRURL == "" {
		// Fleet rows anchor their registration on the first (sorted)
		// target cluster's agent; single-cluster rows on their cluster.
		anchor := row.ClusterID
		if row.DeployMode == types.AddonDeployModeApplicationSet {
			anchor = targets[0].ID
		}
		if err := s.enqueueRegistration(ctx, anchor, row.ID, row.DeployMode, desc, repo, row.RepoPath, namespace, prune, files); err != nil {
			return nil, err
		}
	}
	updated := *row
	updated.State = types.AddonStateManaged
	updated.Source = desc
	updated.ChartVersion = version
	updated.Values = values
	updated.CommitSHA = gitResult.CommitSHA
	updated.PRURL = gitResult.PRURL
	updated.PruneEnabled = updated.PruneEnabled || prune
	event := types.EventAddonUpdated
	auditAction := "addon.updated"
	if action == "enable-prune" {
		event = types.EventAddonPruneEnabled
		auditAction = "addon.prune_enabled"
	}
	err = s.inTx(ctx, func(q db.Querier) error {
		if err := s.store.UpsertClusterAddon(ctx, q, &updated); err != nil {
			return err
		}
		if err := s.recordAudit(ctx, q, row.OrgID, actor, auditAction, row.ID, map[string]any{
			"catalogItem": row.CatalogItem, "cluster": row.ClusterID, "version": version,
			"prune": prune, "commitSha": gitResult.CommitSHA, "prUrl": gitResult.PRURL,
			"authModel": string(authInfo.Model),
		}); err != nil {
			return err
		}
		return s.appendOutbox(ctx, q, row.OrgID, event, types.AddonPayload{
			OrgID: row.OrgID, AddonID: row.ID, CatalogItem: row.CatalogItem, ClusterID: row.ClusterID,
			Version: version, CommitSHA: gitResult.CommitSHA, PRURL: gitResult.PRURL, RepoID: row.RepoID,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("addons: record %s: %w", action, err)
	}
	return &AdoptResult{Addon: &updated, CommitSHA: gitResult.CommitSHA, PRURL: gitResult.PRURL}, nil
}

// markUpdateFailed flips the row to update_failed after a failed update so
// the UI surfaces the failure instead of a silently stale managed row.
func (s *Service) markUpdateFailed(ctx context.Context, orgID string, row *types.ClusterAddon) {
	if err := s.inTx(ctx, func(q db.Querier) error {
		return s.store.SetClusterAddonState(ctx, q, orgID, row.ID, types.AddonStateUpdateFailed)
	}); err != nil {
		slog.Warn("addons: mark update_failed", "addon", row.ID, "error", err)
	}
}

// renderParams bundles the renderer inputs derived from an addon row.
type renderParams struct {
	addonID   string
	name      string
	namespace string
	mode      types.AddonDeployMode
	targets   []renderer.ClusterTarget
	prune     bool
	values    json.RawMessage
	repo      *types.TenantGitRepo
	path      string
}

// render runs the source-agnostic pipeline for one addon. Adoption keeps
// prune off per the params; take-ownership is always set (adopted resources
// pre-exist) — it is harmless on fresh installs.
func (s *Service) render(ctx context.Context, desc types.SourceDescriptor, p renderParams) ([]renderer.RenderedFile, error) {
	return s.renders.Render(ctx, desc, renderer.RenderParams{
		Name: p.name, Namespace: p.namespace,
		ID: p.addonID, AppPrefix: renderer.PrefixAddon,
		DeployMode: p.mode, Clusters: p.targets,
		Prune:       p.prune,
		SyncOptions: []string{TakeOwnershipSyncOption},
		Values:      p.values,
		RepoURL:     orchestrator.RepoURL(p.repo.Repo), BaseBranch: p.repo.BaseBranch,
		Path: p.path, Project: "default",
	})
}

// resolveTargets builds the renderer's cluster targets for adopt.
func (s *Service) resolveTargets(ctx context.Context, orgID string, cluster *types.Cluster, mode types.AddonDeployMode, selector map[string]string) ([]renderer.ClusterTarget, error) {
	if mode == types.AddonDeployModeApplicationSet {
		return s.resolveFleetTargets(ctx, orgID, selector)
	}
	return []renderer.ClusterTarget{{ID: cluster.ID, Name: cluster.Name}}, nil
}

// targetsForRow rebuilds targets from a stored row: fleet rows re-evaluate
// their selector (membership may have drifted since adopt); single-cluster
// rows resolve their recorded cluster.
func (s *Service) targetsForRow(ctx context.Context, row *types.ClusterAddon) ([]renderer.ClusterTarget, error) {
	if row.DeployMode == types.AddonDeployModeApplicationSet {
		return s.resolveFleetTargets(ctx, row.OrgID, row.ClusterSelector)
	}
	cluster, err := s.clusters.GetCluster(ctx, row.ClusterID)
	if err != nil {
		return nil, err
	}
	return []renderer.ClusterTarget{{ID: cluster.ID, Name: cluster.Name}}, nil
}

// resolveRepo resolves the adopt target repo: explicit selector or the
// cluster baseline default. An empty selector with no registry rows maps to
// the no-git-config conflict (mirroring the orchestrator).
func (s *Service) resolveRepo(ctx context.Context, orgID, selector string) (*types.TenantGitRepo, gitprovider.Provider, *gitprovider.AuthInfo, error) {
	if selector == "" {
		selector = gitprovider.RepoSelectorDefault
	}
	row, p, info, err := s.git.ResolveRepo(ctx, orgID, selector)
	if errors.Is(err, inventory.ErrRepoNotFound) && selector == gitprovider.RepoSelectorDefault {
		return nil, nil, nil, ErrNoRepoConfig
	}
	return row, p, info, err
}

// appName is the ArgoCD Application/ApplicationSet name contract:
// inari-addon-<id> single-cluster, inari-addonset-<id> fleet-wide.
func appName(addonID string, mode types.AddonDeployMode) string {
	if mode == types.AddonDeployModeApplicationSet {
		return renderer.PrefixAddonSet + "-" + addonID
	}
	return renderer.PrefixAddon + "-" + addonID
}

// workloadName derives the release/workload name from a catalog item ID
// (platform:cert-manager → cert-manager).
func workloadName(catalogItem string) string {
	if i := strings.Index(catalogItem, ":"); i >= 0 {
		return catalogItem[i+1:]
	}
	return catalogItem
}

// commitPerPolicy writes files per the repo's commit policy (direct commit
// or PR), reusing the provider's CommitFiles/OpenPR paths.
func commitPerPolicy(ctx context.Context, git gitprovider.Provider, repo *types.TenantGitRepo, message string, files []renderer.RenderedFile) (*gitprovider.Result, error) {
	gfiles := make([]gitprovider.File, 0, len(files))
	for _, f := range files {
		gfiles = append(gfiles, gitprovider.File{Path: f.Path, Content: f.Content})
	}
	if repo.CommitPolicy == types.CommitPolicyPullRequest {
		return git.OpenPR(ctx, repo.Repo, repo.BaseBranch, message, "", gfiles)
	}
	return git.CommitFiles(ctx, repo.Repo, repo.BaseBranch, gfiles, message)
}

// enqueueRegistration dispatches the ArgoCD registration command for an
// addon with prune per the flag (OFF at adoption, decision 2).
//
// Application mode uses the existing agentv1.RegisterArgoCDApp contract
// (plan §6); the take-ownership sync option lives in the committed
// application.yaml until the agent contract gains syncOptions. Helm addons
// point the agent-built app at the upstream chart; the committed
// application.yaml (multi-source with git values) stays the authoritative
// desired state.
//
// ApplicationSet mode enqueues EVENT_TYPE_REGISTER_ARGOCD_APPSET with the
// full rendered ApplicationSet manifest in a structpb.Struct bridge payload
// ({name, namespace, manifest}) — the agent cannot rebuild the multi-source
// template from RegisterArgoCDApp fields, and the pinned contract has no
// RegisterArgoCDAppSet message yet (proto mod lands with the agent
// milestone). Queue/dispatch machinery is payload-agnostic (protojson Any),
// so the command flows today; the future agent handler upserts the manifest
// verbatim, mirroring EnsureApplication in argocd/apps.go.
func (s *Service) enqueueRegistration(ctx context.Context, queueCluster, addonID string, mode types.AddonDeployMode,
	desc types.SourceDescriptor, repo *types.TenantGitRepo, path, namespace string, prune bool, files []renderer.RenderedFile) error {
	if s.queue == nil {
		return nil
	}
	if mode == types.AddonDeployModeApplicationSet {
		name := appName(addonID, mode)
		var manifest string
		for _, f := range files {
			if strings.HasSuffix(f.Path, "/applicationset.yaml") {
				manifest = string(f.Content)
			}
		}
		if manifest == "" {
			return errors.New("addons: applicationset render produced no applicationset.yaml")
		}
		payload, err := structpb.NewStruct(map[string]any{
			"name": name, "namespace": "argocd", "manifest": manifest,
		})
		if err != nil {
			return err
		}
		return s.enqueue(ctx, queueCluster, "register-argocd-appset:"+name, RegisterAppSetEventType, payload)
	}

	name := appName(addonID, mode)
	source := &agentv1.ApplicationSource{
		RepoUrl:        orchestrator.RepoURL(repo.Repo),
		Path:           path,
		TargetRevision: repo.BaseBranch,
	}
	if desc.Kind == types.SourceKindHelm && desc.Helm != nil {
		source = &agentv1.ApplicationSource{
			RepoUrl:        desc.Helm.RepoURL,
			Chart:          desc.Helm.Chart,
			TargetRevision: desc.Helm.Version,
		}
	}
	return s.enqueue(ctx, queueCluster, "register-argocd-app:"+name,
		agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_REGISTER_ARGOCD_APP),
		&agentv1.RegisterArgoCDApp{
			CommandId:            name,
			Name:                 name,
			Project:              "default",
			Source:               source,
			DestinationServer:    "https://kubernetes.default.svc",
			DestinationNamespace: namespace,
			SyncPolicy:           &agentv1.SyncPolicy{Automated: true, SelfHeal: true, Prune: prune},
		})
}

// enqueue marshals one proto payload into a durable agent command.
func (s *Service) enqueue(ctx context.Context, clusterID, queueID, eventType string, payload proto.Message) error {
	any, err := anypb.New(payload)
	if err != nil {
		return err
	}
	raw, err := protojson.Marshal(any)
	if err != nil {
		return err
	}
	return s.queue.Enqueue(ctx, &types.AgentCommand{
		ID:        queueID,
		ClusterID: clusterID,
		Type:      eventType,
		Payload:   raw,
	})
}

func (s *Service) querier() db.Querier {
	if s.db != nil {
		return s.db.Pool
	}
	return nil
}

// inTx runs fn inside a DB transaction when a DB is wired; unit tests
// without a DB run fn directly against the pool-less store seam (mirrors
// the gitrepos service convention).
func (s *Service) inTx(ctx context.Context, fn func(q db.Querier) error) error {
	if s.db == nil {
		return fn(nil)
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error { return fn(tx) })
}

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
		Action: action, ObjectType: "cluster_addon", ObjectID: objectID,
		Payload: json.RawMessage(raw),
	}
	if err := impersonation.Stamp(ctx, ev); err != nil {
		return err
	}
	return s.audit.Record(ctx, q, ev)
}

func (s *Service) appendOutbox(ctx context.Context, q db.Querier, orgID, eventType string, payload types.AddonPayload) error {
	if s.audit == nil {
		return nil
	}
	return audit.AppendOutbox(ctx, q, orgID, eventType, payload)
}

// ---------------------------------------------------------------------------
// Fleet reconciliation (decision 8)

// FleetReconciler is the outbox consumer re-rendering managed ApplicationSet
// addons when fleet membership may have changed: cluster.registered covers
// both registration and label changes (labels only mutate via
// re-registration), cluster.deleted shrinks the fleet. Re-render + commit
// happens only when the rendered ApplicationSet actually changed (ReadFile
// compare), so the handler is idempotent and quiet on unrelated events.
type FleetReconciler struct {
	svc *Service
	log *slog.Logger
}

// NewFleetReconciler wires the decision-8 consumer.
func NewFleetReconciler(svc *Service, log *slog.Logger) *FleetReconciler {
	if log == nil {
		log = slog.Default()
	}
	return &FleetReconciler{svc: svc, log: log}
}

// EventTypes implements audit.Handler.
func (h *FleetReconciler) EventTypes() []string {
	return []string{types.EventClusterRegistered, types.EventClusterDeleted}
}

// Handle implements audit.Handler.
func (h *FleetReconciler) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	var p types.ClusterPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return fmt.Errorf("addons: fleet reconcile: payload: %w", err)
	}
	if p.OrgID == "" {
		return nil
	}
	return h.svc.RerenderFleetAddons(ctx, p.OrgID)
}

// RerenderFleetAddons re-renders every managed ApplicationSet addon of the
// org against current fleet membership and commits on drift only.
func (s *Service) RerenderFleetAddons(ctx context.Context, orgID string) error {
	rows, err := s.store.ListClusterAddons(ctx, s.querier(), orgID, "")
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.DeployMode != types.AddonDeployModeApplicationSet || row.State != types.AddonStateManaged {
			continue
		}
		if err := s.rerenderFleetAddon(ctx, row); err != nil {
			// One bad row must not starve the others; the outbox redelivers.
			slog.Warn("addons: fleet re-render", "addon", row.ID, "error", err)
		}
	}
	return nil
}

// rerenderFleetAddon re-renders one fleet addon's ApplicationSet and commits
// per repo policy when the manifest changed. Registration re-enqueue is not
// needed: the ApplicationSet CR is unchanged in name/namespace, and ArgoCD
// picks up the new manifest from git on the next sync.
func (s *Service) rerenderFleetAddon(ctx context.Context, row *types.ClusterAddon) error {
	repo, provider, _, err := s.git.ResolveRepo(ctx, row.OrgID, row.RepoID)
	if err != nil {
		return err
	}
	targets, err := s.resolveFleetTargets(ctx, row.OrgID, row.ClusterSelector)
	if errors.Is(err, ErrEmptyFleet) {
		return nil // fleet drained to zero: keep the last render (deletion is a separate flow)
	}
	if err != nil {
		return err
	}
	namespace := row.Namespace
	if namespace == "" {
		namespace = workloadName(row.CatalogItem)
	}
	files, err := s.render(ctx, row.Source, renderParams{
		addonID: row.ID, name: workloadName(row.CatalogItem), namespace: namespace,
		mode: row.DeployMode, targets: targets, prune: row.PruneEnabled,
		values: row.Values, repo: repo, path: row.RepoPath,
	})
	if err != nil {
		return err
	}
	var changed []renderer.RenderedFile
	for _, f := range files {
		cur, err := provider.ReadFile(ctx, repo.Repo, repo.BaseBranch, f.Path)
		if err != nil {
			return err
		}
		if cur != string(f.Content) {
			changed = append(changed, f)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	message := fmt.Sprintf("fleet membership update for addon %s (addon %s)", row.CatalogItem, row.ID)
	if _, err := commitPerPolicy(ctx, provider, repo, message, changed); err != nil {
		return fmt.Errorf("addons: fleet re-render commit: %w", err)
	}
	return nil
}
