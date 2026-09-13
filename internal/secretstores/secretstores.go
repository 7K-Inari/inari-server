// Package secretstores implements the ESO SecretStore registry (Settings
// design §3.2): platform- and cluster-scoped SecretStore declarations whose
// credentials stay cluster-side (authSecretRef only — plan §4.1). Mutations
// are desired-state: the registry row + audit + outbox commit in one TX,
// then apply/delete commands fan out over the agent command queue. Status
// is a projection over agent_commands, never a stored row.
package secretstores

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// CommandQueue enqueues desired-state commands for agents (agentgateway.Queue seam).
type CommandQueue interface {
	Enqueue(ctx context.Context, cmd *types.AgentCommand) error
}

// ClusterLister resolves an org's clusters (clusterregistry.Service seam).
type ClusterLister interface {
	ListClusters(ctx context.Context, orgID string) ([]types.Cluster, error)
}

// SetResolver resolves ClusterSets for target selectors (fleetmanager.Service seam).
type SetResolver interface {
	GetClusterSet(ctx context.Context, orgID, id string) (*types.ClusterSet, error)
	ResolveClusters(ctx context.Context, orgID string, selector map[string]string) ([]types.Cluster, error)
}

// Service is the secret-stores module facade.
type Service struct {
	db       *db.DB
	store    *Store
	audit    *audit.Store
	queue    CommandQueue
	clusters ClusterLister
	sets     SetResolver
}

func NewService(d *db.DB, store *Store, auditStore *audit.Store, queue CommandQueue, clusters ClusterLister, sets SetResolver) *Service {
	return &Service{db: d, store: store, audit: auditStore, queue: queue, clusters: clusters, sets: sets}
}

func newUUID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

func validateStore(st *types.SecretStore) error {
	if err := ValidateName(st.Name); err != nil {
		return err
	}
	if err := ValidateScope(st.Scope); err != nil {
		return err
	}
	if err := ValidateTargets(st.Targets); err != nil {
		return err
	}
	return ValidateProvider(st.Provider)
}

// validateClusterOwnership enforces tenant isolation on explicit clusterIds
// targets (principle 1): every listed cluster must belong to the org, or a
// tenant admin could enqueue SecretStoreApply commands into another org's
// agent queue. ClusterSetRef targets are already org-scoped by ResolveClusters.
func (s *Service) validateClusterOwnership(ctx context.Context, orgID string, clusterIDs []string) error {
	if len(clusterIDs) == 0 {
		return nil
	}
	owned, err := s.clusters.ListClusters(ctx, orgID)
	if err != nil {
		return err
	}
	ownedIDs := make(map[string]bool, len(owned))
	for _, c := range owned {
		ownedIDs[c.ID] = true
	}
	for _, id := range clusterIDs {
		if !ownedIDs[id] {
			return fmt.Errorf("%w: cluster %q is not registered to this organization", ErrInvalidInput, id)
		}
	}
	return nil
}

// resolveTargets expands the store's targets to concrete cluster IDs.
func (s *Service) resolveTargets(ctx context.Context, st *types.SecretStore) ([]string, error) {
	t := st.Targets
	if t.ClusterSetRef != "" {
		cs, err := s.sets.GetClusterSet(ctx, st.OrgID, t.ClusterSetRef)
		if err != nil {
			return nil, err
		}
		members, err := s.sets.ResolveClusters(ctx, st.OrgID, cs.LabelSelector)
		if err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(members))
		for _, c := range members {
			ids = append(ids, c.ID)
		}
		return ids, nil
	}
	return append([]string(nil), t.ClusterIDs...), nil
}

// resolveTargetsByState splits resolved targets into deliverable and
// cordoned clusters: cordon blocks new deploys (clusterregistry lifecycle),
// so fan-out skips cordoned clusters while workloads keep running. Clusters
// the lister does not know are treated as deliverable (fail-open matches the
// enqueue-and-reconcile contract).
func (s *Service) resolveTargetsByState(ctx context.Context, st *types.SecretStore) (deliverable, cordoned []string, err error) {
	ids, err := s.resolveTargets(ctx, st)
	if err != nil {
		return nil, nil, err
	}
	states := map[string]types.ClusterState{}
	if s.clusters != nil {
		owned, err := s.clusters.ListClusters(ctx, st.OrgID)
		if err != nil {
			return nil, nil, err
		}
		for _, c := range owned {
			states[c.ID] = c.State
		}
	}
	for _, id := range ids {
		if states[id] == types.ClusterStateCordoned {
			cordoned = append(cordoned, id)
			continue
		}
		deliverable = append(deliverable, id)
	}
	return deliverable, cordoned, nil
}

// targetDiff returns the sorted cluster IDs present in old but not in new.
func targetDiff(oldIDs, newIDs []string) []string {
	keep := make(map[string]bool, len(newIDs))
	for _, id := range newIDs {
		keep[id] = true
	}
	var removed []string
	for _, id := range oldIDs {
		if !keep[id] {
			removed = append(removed, id)
		}
	}
	sort.Strings(removed)
	return removed
}

// stateRepoPath is the directory in the tenant state repo where SecretStore
// manifests are committed (synced into clusters by the tenant-local ArgoCD).
const stateRepoPath = "secretstores"

// applyProto builds the contract message for one apply command. Credential
// material never transits: only authSecretRef (plan §4.1).
func applyProto(st *types.SecretStore, commandID string) (*agentv1.SecretStoreApply, error) {
	m := &agentv1.SecretStoreApply{
		CommandId: commandID,
		Name:      st.Name,
		Scope:     st.Scope,
		Target:    &agentv1.GitTarget{Path: stateRepoPath},
		Policy:    agentv1.CommitPolicy_COMMIT_POLICY_DIRECT_COMMIT,
	}
	ref := func(r types.SecretRef) *agentv1.SecretRef {
		return &agentv1.SecretRef{Name: r.Name, Namespace: r.Namespace}
	}
	switch p := st.Provider; {
	case p.AWSSM != nil:
		m.Provider = &agentv1.SecretStoreApply_AwsSm{AwsSm: &agentv1.AwsSMProvider{
			Region: p.AWSSM.Region, AuthSecretRef: ref(p.AWSSM.AuthSecretRef)}}
	case p.Vault != nil:
		m.Provider = &agentv1.SecretStoreApply_Vault{Vault: &agentv1.VaultProvider{
			Server: p.Vault.Server, Path: p.Vault.Path, AuthSecretRef: ref(p.Vault.AuthSecretRef)}}
	case p.GCPSM != nil:
		m.Provider = &agentv1.SecretStoreApply_GcpSm{GcpSm: &agentv1.GcpSMProvider{
			ProjectId: p.GCPSM.ProjectID, AuthSecretRef: ref(p.GCPSM.AuthSecretRef)}}
	case p.AzureKV != nil:
		m.Provider = &agentv1.SecretStoreApply_AzureKv{AzureKv: &agentv1.AzureKVProvider{
			VaultUrl: p.AzureKV.VaultURL, TenantId: p.AzureKV.TenantID, AuthSecretRef: ref(p.AzureKV.AuthSecretRef)}}
	default:
		return nil, fmt.Errorf("%w: store %q has no provider", ErrInvalidInput, st.ID)
	}
	return m, nil
}

// applyCommand builds the queued apply command for one target cluster.
func applyCommand(st *types.SecretStore, clusterID string, nonce int64) (*types.AgentCommand, error) {
	id := fmt.Sprintf("secretstore:%s:%s:%d", st.ID, clusterID, nonce)
	m, err := applyProto(st, id)
	if err != nil {
		return nil, err
	}
	any, err := anypb.New(m)
	if err != nil {
		return nil, err
	}
	raw, err := protojson.Marshal(any)
	if err != nil {
		return nil, err
	}
	return &types.AgentCommand{
		ID:        id,
		ClusterID: clusterID,
		Type:      agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_SECRET_STORE_APPLY),
		Payload:   raw,
	}, nil
}

// deleteCommand builds the queued delete command for one target cluster.
func deleteCommand(st *types.SecretStore, clusterID string, nonce int64) (*types.AgentCommand, error) {
	id := fmt.Sprintf("secretstore:%s:%s:%d", st.ID, clusterID, nonce)
	any, err := anypb.New(&agentv1.SecretStoreDelete{
		CommandId: id,
		Name:      st.Name,
		Scope:     st.Scope,
		Target:    &agentv1.GitTarget{Path: stateRepoPath},
		Policy:    agentv1.CommitPolicy_COMMIT_POLICY_DIRECT_COMMIT,
	})
	if err != nil {
		return nil, err
	}
	raw, err := protojson.Marshal(any)
	if err != nil {
		return nil, err
	}
	return &types.AgentCommand{
		ID:        id,
		ClusterID: clusterID,
		Type:      agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_SECRET_STORE_DELETE),
		Payload:   raw,
	}, nil
}

// fanout enqueues one apply command per resolved deliverable target cluster
// after the registry mutation has committed; cordoned clusters are skipped
// (cordon blocks new deploys). Command IDs embed a per-mutation nonce: the
// queue dedupes on ID, so re-applies (updates) and deletes must NOT reuse
// the create-time ID or they would be silently dropped. Failures are logged
// (desired state is eventually reconciled) and never roll back the committed
// registry row.
func (s *Service) fanout(ctx context.Context, st *types.SecretStore) {
	s.enqueue(ctx, st, false, nil)
}

// fanoutDelete enqueues delete commands to all resolved targets, including
// cordoned clusters: cordon blocks new deploys, not pruning — a stale store
// must still be removed (the registry row is gone, so nothing would ever
// reconcile it).
func (s *Service) fanoutDelete(ctx context.Context, st *types.SecretStore) {
	s.enqueue(ctx, st, true, nil)
}

// fanoutUpdate enqueues apply commands to the store's deliverable targets
// and delete commands to clusters removed from the target set, so stale
// SecretStores are pruned from clusters no longer targeted.
func (s *Service) fanoutUpdate(ctx context.Context, st *types.SecretStore, removedTargets []string) {
	s.enqueue(ctx, st, false, removedTargets)
}

func (s *Service) enqueue(ctx context.Context, st *types.SecretStore, delete bool, removedTargets []string) {
	if s.queue == nil {
		return
	}
	deliverable, cordoned, err := s.resolveTargetsByState(ctx, st)
	if err != nil {
		slog.Error("secretstores: resolve targets", "store", st.ID, "error", err)
		return
	}
	nonce := time.Now().UnixNano()
	enqueue := func(cmd *types.AgentCommand, err error) {
		if err != nil {
			slog.Error("secretstores: build command", "store", st.ID, "error", err)
			return
		}
		if err := s.queue.Enqueue(ctx, cmd); err != nil {
			slog.Error("secretstores: enqueue command", "command", cmd.ID, "error", err)
		}
	}
	if delete {
		for _, clusterID := range append(deliverable, cordoned...) {
			enqueue(deleteCommand(st, clusterID, nonce))
		}
		return
	}
	for _, clusterID := range deliverable {
		enqueue(applyCommand(st, clusterID, nonce))
	}
	for _, clusterID := range removedTargets {
		enqueue(deleteCommand(st, clusterID, nonce))
	}
}

// Create registers a new store and fans out apply commands to its targets.
func (s *Service) Create(ctx context.Context, actor string, in types.SecretStore) (*types.SecretStore, error) {
	if err := validateStore(&in); err != nil {
		return nil, err
	}
	if err := s.validateClusterOwnership(ctx, in.OrgID, in.Targets.ClusterIDs); err != nil {
		return nil, err
	}
	in.ID = "secretstore:" + newUUID()
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.Create(ctx, tx, &in); err != nil {
			return err
		}
		payload, err := json.Marshal(types.SecretStorePayload{
			OrgID: in.OrgID, StoreID: in.ID, Name: in.Name, Scope: in.Scope,
		})
		if err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: in.OrgID, Actor: actor, Action: types.EventSecretStoreCreated,
			ObjectType: "secret_store", ObjectID: in.ID, Payload: payload,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, in.OrgID, types.EventSecretStoreCreated, types.SecretStorePayload{
			OrgID: in.OrgID, StoreID: in.ID, Name: in.Name, Scope: in.Scope,
		})
	})
	if err != nil {
		return nil, err
	}
	s.fanout(ctx, &in)
	return &in, nil
}

// Get returns one store visible to the org (own cluster-scoped or any
// platform-scoped store).
func (s *Service) Get(ctx context.Context, orgID, name string) (*types.SecretStore, error) {
	return s.store.Get(ctx, s.db.Pool, orgID, name)
}

// List returns the org's cluster-scoped stores plus all platform stores.
func (s *Service) List(ctx context.Context, orgID string) ([]types.SecretStore, error) {
	return s.store.List(ctx, s.db.Pool, orgID)
}

// Update replaces targets/provider of an existing store. Platform stores are
// org-agnostic; the caller's authz is enforced at the HTTP layer.
func (s *Service) Update(ctx context.Context, actor, orgID, name string, targets *types.SecretStoreTargets, provider *types.SecretStoreProvider) (*types.SecretStore, error) {
	st, err := s.store.Get(ctx, s.db.Pool, orgID, name)
	if err != nil {
		return nil, err
	}
	// Capture the full current target set (including cordoned clusters) before
	// the mutation so every removed cluster is pruned after the update commits
	// — a cluster cordoned before removal still holds the stale manifest.
	oldTargets, err := s.resolveTargets(ctx, st)
	if err != nil {
		return nil, err
	}
	if targets != nil {
		st.Targets = *targets
	}
	if provider != nil {
		st.Provider = *provider
	}
	if err := ValidateTargets(st.Targets); err != nil {
		return nil, err
	}
	if err := ValidateProvider(st.Provider); err != nil {
		return nil, err
	}
	if err := s.validateClusterOwnership(ctx, st.OrgID, st.Targets.ClusterIDs); err != nil {
		return nil, err
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.Update(ctx, tx, st); err != nil {
			return err
		}
		payload, err := json.Marshal(types.SecretStorePayload{
			OrgID: st.OrgID, StoreID: st.ID, Name: st.Name, Scope: st.Scope,
		})
		if err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: st.OrgID, Actor: actor, Action: types.EventSecretStoreUpdated,
			ObjectType: "secret_store", ObjectID: st.ID, Payload: payload,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, st.OrgID, types.EventSecretStoreUpdated, types.SecretStorePayload{
			OrgID: st.OrgID, StoreID: st.ID, Name: st.Name, Scope: st.Scope,
		})
	})
	if err != nil {
		return nil, err
	}
	newTargets, err := s.resolveTargets(ctx, st)
	if err != nil {
		// The row is committed; log and still report the update.
		slog.Error("secretstores: resolve updated targets", "store", st.ID, "error", err)
		newTargets = nil
	}
	s.fanoutUpdate(ctx, st, targetDiff(oldTargets, newTargets))
	return st, nil
}

// Delete removes a store and fans out delete commands to its targets.
func (s *Service) Delete(ctx context.Context, actor, orgID, name string) error {
	st, err := s.store.Get(ctx, s.db.Pool, orgID, name)
	if err != nil {
		return err
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.Delete(ctx, tx, st.ID); err != nil {
			return err
		}
		payload, err := json.Marshal(types.SecretStorePayload{
			OrgID: st.OrgID, StoreID: st.ID, Name: st.Name, Scope: st.Scope,
		})
		if err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: st.OrgID, Actor: actor, Action: types.EventSecretStoreDeleted,
			ObjectType: "secret_store", ObjectID: st.ID, Payload: payload,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, st.OrgID, types.EventSecretStoreDeleted, types.SecretStorePayload{
			OrgID: st.OrgID, StoreID: st.ID, Name: st.Name, Scope: st.Scope,
		})
	})
	if err != nil {
		return err
	}
	s.fanoutDelete(ctx, st)
	return nil
}

// Status projects delivery state for one store over agent_commands: every
// resolved deliverable target cluster must have an acked apply command for
// delivered. Cordoned targets are reported separately and excluded from the
// delivered computation (cordon blocks new deploys by design).
func (s *Service) Status(ctx context.Context, orgID, name string) (*types.SecretStoreStatus, error) {
	st, err := s.store.Get(ctx, s.db.Pool, orgID, name)
	if err != nil {
		return nil, err
	}
	clusterIDs, cordoned, err := s.resolveTargetsByState(ctx, st)
	if err != nil {
		return nil, err
	}
	states, err := s.store.CommandStates(ctx, s.db.Pool, st.ID)
	if err != nil {
		return nil, err
	}
	byCluster := map[string]commandState{}
	for _, cs := range states {
		byCluster[cs.ClusterID] = cs
	}
	sort.Strings(clusterIDs)
	sort.Strings(cordoned)
	status := &types.SecretStoreStatus{Delivered: len(clusterIDs) > 0}
	for _, clusterID := range clusterIDs {
		cond := types.SecretStoreCondition{ClusterID: clusterID, Type: "Ready"}
		cs, ok := byCluster[clusterID]
		switch {
		case !ok:
			cond.Status, cond.Reason = "False", "Pending"
			status.Delivered = false
		case cs.Status == types.CommandStatusAcked:
			cond.Status, cond.Reason, cond.Message = "True", "Delivered", cs.Message
		case cs.Status == types.CommandStatusNacked:
			cond.Status, cond.Reason, cond.Message = "False", "Failed", cs.Message
			status.Delivered = false
		default:
			cond.Status, cond.Reason = "False", "Pending"
			status.Delivered = false
		}
		status.Conditions = append(status.Conditions, cond)
	}
	for _, clusterID := range cordoned {
		status.Conditions = append(status.Conditions, types.SecretStoreCondition{
			ClusterID: clusterID, Type: "Ready", Status: "False", Reason: "Cordoned",
			Message: "cluster is cordoned; delivery deferred until uncordon",
		})
	}
	return status, nil
}

// PlatformStoreName resolves the platform-scoped store with the given name,
// replacing the hardcoded "inari-platform" config fallback in the agent
// gateway. ErrNotFound means the registry has no such store and callers
// should fall back to their configured default.
func (s *Service) PlatformStoreName(ctx context.Context, name string) (string, error) {
	st, err := s.store.Get(ctx, s.db.Pool, "", name)
	if err != nil {
		return "", err
	}
	if st.Scope != types.SecretStoreScopePlatform {
		return "", fmt.Errorf("%w: store %q is not platform-scoped", ErrNotFound, name)
	}
	return st.Name, nil
}
