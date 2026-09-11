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

// fanout enqueues one apply/delete command per resolved target cluster after
// the registry mutation has committed. Command IDs embed a per-mutation nonce:
// the queue dedupes on ID, so re-applies (updates) and deletes must NOT reuse
// the create-time ID or they would be silently dropped. Failures are logged
// (desired state is eventually reconciled) and never roll back the committed
// registry row.
func (s *Service) fanout(ctx context.Context, st *types.SecretStore, cmdType string) {
	if s.queue == nil {
		return
	}
	clusterIDs, err := s.resolveTargets(ctx, st)
	if err != nil {
		slog.Error("secretstores: resolve targets", "store", st.ID, "error", err)
		return
	}
	payload, err := json.Marshal(st)
	if err != nil {
		slog.Error("secretstores: marshal command payload", "store", st.ID, "error", err)
		return
	}
	nonce := time.Now().UnixNano()
	for _, clusterID := range clusterIDs {
		cmd := &types.AgentCommand{
			ID:        fmt.Sprintf("secretstore:%s:%s:%d", st.ID, clusterID, nonce),
			ClusterID: clusterID,
			Type:      cmdType,
			Payload:   payload,
		}
		if err := s.queue.Enqueue(ctx, cmd); err != nil {
			slog.Error("secretstores: enqueue command", "command", cmd.ID, "error", err)
		}
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
	s.fanout(ctx, &in, types.AgentCommandSecretStoreApply)
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
	s.fanout(ctx, st, types.AgentCommandSecretStoreApply)
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
	s.fanout(ctx, st, types.AgentCommandSecretStoreDelete)
	return nil
}

// Status projects delivery state for one store over agent_commands: every
// resolved target cluster must have an acked apply command for delivered.
func (s *Service) Status(ctx context.Context, orgID, name string) (*types.SecretStoreStatus, error) {
	st, err := s.store.Get(ctx, s.db.Pool, orgID, name)
	if err != nil {
		return nil, err
	}
	clusterIDs, err := s.resolveTargets(ctx, st)
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
