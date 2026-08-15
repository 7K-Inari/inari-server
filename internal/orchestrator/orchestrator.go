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
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/yaml.v3"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// CatalogResolver is the catalog seam the orchestrator needs.
type CatalogResolver interface {
	GetItemByID(ctx context.Context, itemID string) (*types.CatalogItem, error)
	EffectiveVersion(ctx context.Context, orgID, itemID, channel string) (string, error)
	GetVersion(ctx context.Context, itemID, version string) (*types.CatalogItemVersion, error)
}

// ClusterResolver is the cluster registry seam.
type ClusterResolver interface {
	GetCluster(ctx context.Context, id string) (*types.Cluster, error)
}

// Gate is the approvals seam.
type Gate interface {
	Gate(ctx context.Context, orgID string, item *types.CatalogItem, version, clusterID string, spec []byte, requester string) (*approvals.GateResult, error)
}

// Queue is the agent command queue seam (agentgateway.Queue).
type Queue interface {
	Enqueue(ctx context.Context, cmd *types.AgentCommand) error
}

// ErrNoGitConfig is returned when the tenant has no state repo configured.
var ErrNoGitConfig = fmt.Errorf("orchestrator: tenant has no git config (provisioned by the tenant zone factory)")

// ErrClusterNotActive blocks deploys to non-active clusters (§5.11 cordon).
var ErrClusterNotActive = fmt.Errorf("orchestrator: cluster is not active")

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
	queue     Queue
	git       gitprovider.Provider
	audit     *audit.Store
}

func NewService(d *db.DB, instances *inventory.Store, catalog CatalogResolver, clusters ClusterResolver,
	gate Gate, queue Queue, git gitprovider.Provider, auditStore *audit.Store) *Service {
	return &Service{
		db: d, instances: instances, catalog: catalog, clusters: clusters,
		gate: gate, queue: queue, git: git, audit: auditStore,
	}
}

// Deploy turns a deploy request into desired state. When the item's
// approval policy requires review, only an approval request is created and
// the caller must re-issue Deploy after approval (M2 basic flow).
func (s *Service) Deploy(ctx context.Context, req DeployRequest) (*DeployResult, error) {
	cluster, err := s.clusters.GetCluster(ctx, req.ClusterID)
	if err != nil {
		return nil, err
	}
	if cluster.OrgID != req.OrgID {
		return nil, fmt.Errorf("orchestrator: cluster does not belong to tenant")
	}
	if cluster.State != types.ClusterStateActive && cluster.State != types.ClusterStateDegraded {
		return nil, ErrClusterNotActive
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

	gate, err := s.gate.Gate(ctx, req.OrgID, item, version, req.ClusterID, req.Spec, req.Requester)
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
	ver, err := s.catalog.GetVersion(ctx, req.ItemID, version)
	if err != nil {
		return nil, err
	}
	gitCfg, err := s.instances.GitConfig(ctx, s.db.Pool, req.OrgID)
	if err != nil {
		return nil, err
	}
	if gitCfg == nil {
		return nil, ErrNoGitConfig
	}
	if err := s.git.EnsureRepo(ctx, gitCfg.Repo); err != nil {
		return nil, err
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

	manifest, err := RenderInstanceManifest(ver, name, namespace, req.Spec)
	if err != nil {
		return nil, err
	}
	path := RepoPath(req.ClusterID, req.ItemID, instanceID)
	app := RenderArgoCDApplication(ApplicationParams{
		Name:           "inari-" + instanceID,
		Project:        "default",
		RepoURL:        repoURL(gitCfg.Repo),
		Path:           path,
		TargetRevision: gitCfg.BaseBranch,
		DestNamespace:  namespace,
	})
	files := []gitprovider.File{
		{Path: path + "/instance.yaml", Content: manifest},
		{Path: path + "/application.yaml", Content: app},
	}

	message := fmt.Sprintf("deploy %s@%s to %s (instance %s)", req.ItemID, version, req.ClusterID, instanceID)
	var gitResult *gitprovider.Result
	if gitCfg.CommitPolicy == types.CommitPolicyPullRequest {
		gitResult, err = s.git.OpenPR(ctx, gitCfg.Repo, gitCfg.BaseBranch, message, "", files)
	} else {
		gitResult, err = s.git.CommitFiles(ctx, gitCfg.Repo, gitCfg.BaseBranch, files, message)
	}
	if err != nil {
		return nil, fmt.Errorf("orchestrator: git write: %w", err)
	}

	// For pull-request policy the app registers after the PR merges (M2:
	// documented gap; the merge webhook wiring lands with Fleet Manager).
	if gitResult.PRURL == "" {
		if err := s.enqueueAppRegistration(ctx, req.ClusterID, instanceID, gitCfg, path, namespace); err != nil {
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
				CommitSHA: gitResult.CommitSHA, PRURL: gitResult.PRURL, Generation: 1,
			}
			if err := s.instances.Create(ctx, tx, inst); err != nil {
				return err
			}
		} else if err := s.instances.MarkDeployed(ctx, tx, instanceID, version, gitResult.CommitSHA, gitResult.PRURL, state, true); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: req.OrgID, Actor: req.Requester, Action: "deploy.requested",
			ObjectType: "resource_instance", ObjectID: instanceID,
			Payload: json.RawMessage(fmt.Sprintf(`{"item":%q,"version":%q,"cluster":%q}`, req.ItemID, version, req.ClusterID)),
		}); err != nil {
			return err
		}
		eventType := types.EventDeployRequested
		if existing != nil {
			eventType = types.EventInstanceUpgraded
		}
		return audit.AppendOutbox(ctx, tx, req.OrgID, eventType, types.DeployRequestedPayload{
			OrgID: req.OrgID, InstanceID: instanceID, ItemID: req.ItemID, ClusterID: req.ClusterID,
			Version: version, CommitSHA: gitResult.CommitSHA, PRURL: gitResult.PRURL,
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
func (s *Service) enqueueAppRegistration(ctx context.Context, clusterID, instanceID string, gitCfg *types.TenantGitConfig, path, namespace string) error {
	cmd := &agentv1.RegisterArgoCDApp{
		CommandId: instanceID,
		Name:      "inari-" + instanceID,
		Project:   "default",
		Source: &agentv1.ApplicationSource{
			RepoUrl:        repoURL(gitCfg.Repo),
			Path:           path,
			TargetRevision: gitCfg.BaseBranch,
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

// Upgrade re-deploys an existing instance at a newer version through the
// same path (§5.11 resource upgrade flow).
func (s *Service) Upgrade(ctx context.Context, orgID, instanceID, toVersion, requester string) (*DeployResult, error) {
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
	gate, err := s.gate.Gate(ctx, orgID, item, toVersion, existing.ClusterID, existing.Spec, requester)
	if err != nil {
		return nil, err
	}
	if !gate.Approved {
		return &DeployResult{Status: "pending_approval", ApprovalID: gate.ApprovalID, Version: toVersion}, nil
	}
	return s.apply(ctx, DeployRequest{
		OrgID: orgID, ClusterID: existing.ClusterID, ItemID: existing.CatalogItemID,
		Version: toVersion, OwnerTeam: existing.OwnerTeam, Spec: existing.Spec, Requester: requester,
	}, item, toVersion, existing)
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
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.instances.UpsertGitConfig(ctx, tx, cfg); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: cfg.OrgID, Actor: actor, Action: "git.config_set",
			ObjectType: "tenant", ObjectID: cfg.OrgID,
			Payload: json.RawMessage(fmt.Sprintf(`{"repo":%q,"commitPolicy":%q}`, cfg.Repo, cfg.CommitPolicy)),
		})
	})
}

// GetGitConfig reads the tenant's git config.
func (s *Service) GetGitConfig(ctx context.Context, orgID string) (*types.TenantGitConfig, error) {
	return s.instances.GitConfig(ctx, s.db.Pool, orgID)
}

func repoURL(repo string) string {
	if len(repo) > 8 && repo[:8] == "https://" {
		return repo
	}
	return "https://github.com/" + repo
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
