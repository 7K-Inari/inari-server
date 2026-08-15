// Package inventory implements the Resources Inventory module (plan §5.2,
// §5.9): ResourceInstance records built from agent status-update streams
// plus the query API feeding the console resources view.
package inventory

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// StatusUpdate is the internal form of an agent status-update event.
type StatusUpdate struct {
	Resource types.ResourceRef
	Health   string
	Sync     string
	Message  string
}

// VersionResolver reports the latest catalog version of an item (catalog
// seam) — used for the "new version available" badge.
type VersionResolver interface {
	LatestVersion(ctx context.Context, itemID, channel string) (string, error)
	LatestVersions(ctx context.Context, itemIDs []string) (map[string]string, error)
}

// Service applies status updates and serves instance queries.
type Service struct {
	db      *db.DB
	store   *Store
	audit   *audit.Store
	catalog VersionResolver
}

func NewService(d *db.DB, store *Store, auditStore *audit.Store, catalog VersionResolver) *Service {
	return &Service{db: d, store: store, audit: auditStore, catalog: catalog}
}

// InstanceView adds computed fields for the console.
type InstanceView struct {
	types.ResourceInstance
	// LatestVersion is the newest catalog version (badge source).
	LatestVersion string `json:"latestVersion,omitempty"`
	// NewVersionAvailable is true when the instance runs an older version.
	NewVersionAvailable bool `json:"newVersionAvailable"`
}

func deriveState(health string) types.InstanceState {
	switch health {
	case "healthy":
		return types.InstanceStateRunning
	case "degraded", "missing":
		return types.InstanceStateDegraded
	case "unknown", "":
		return types.InstanceStateDeploying
	default: // progressing, suspended
		return types.InstanceStateDeploying
	}
}

// ApplyStatus folds one agent status-update into the matching instance.
// Unknown resources (not Inari-managed) are ignored without error.
func (s *Service) ApplyStatus(ctx context.Context, clusterID string, upd StatusUpdate) (bool, error) {
	state := deriveState(upd.Health)
	var matched bool
	var inst *types.ResourceInstance
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		var err error
		inst, matched, err = s.store.ApplyStatus(ctx, tx, clusterID, upd.Resource, upd.Health, upd.Sync, upd.Message, state)
		if err != nil || !matched {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: inst.OrgID, Actor: "agent:" + clusterID, Action: "instance.status",
			ObjectType: "resource_instance", ObjectID: inst.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, inst.OrgID, types.EventInstanceStatus, types.InstancePayload{
			OrgID: inst.OrgID, InstanceID: inst.ID, ItemID: inst.CatalogItemID,
			ClusterID: clusterID, Health: upd.Health,
		})
	})
	if err != nil {
		return false, fmt.Errorf("inventory: apply status: %w", err)
	}
	return matched, nil
}

// Get returns one instance with the version badge computed.
func (s *Service) Get(ctx context.Context, orgID, id string) (*InstanceView, error) {
	inst, err := s.store.Get(ctx, s.db.Pool, id)
	if err != nil {
		return nil, err
	}
	if inst.OrgID != orgID {
		return nil, ErrInstanceNotFound
	}
	return s.withBadge(ctx, inst)
}

// List returns instances for an org with badges computed (one batch query
// for latest versions, no per-instance fan-out).
func (s *Service) List(ctx context.Context, orgID string, f ListFilters) ([]InstanceView, error) {
	instances, err := s.store.List(ctx, s.db.Pool, orgID, f)
	if err != nil {
		return nil, err
	}
	var latest map[string]string
	if s.catalog != nil {
		seen := map[string]bool{}
		var ids []string
		for i := range instances {
			if id := instances[i].CatalogItemID; !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		latest, err = s.catalog.LatestVersions(ctx, ids)
		if err != nil {
			return nil, err
		}
	}
	out := make([]InstanceView, 0, len(instances))
	for i := range instances {
		v := &InstanceView{ResourceInstance: instances[i]}
		if l := latest[instances[i].CatalogItemID]; l != "" {
			v.LatestVersion = l
			v.NewVersionAvailable = l != instances[i].Version
		}
		out = append(out, *v)
	}
	return out, nil
}

func (s *Service) withBadge(ctx context.Context, inst *types.ResourceInstance) (*InstanceView, error) {
	v := &InstanceView{ResourceInstance: *inst}
	if s.catalog == nil {
		return v, nil
	}
	latest, err := s.catalog.LatestVersion(ctx, inst.CatalogItemID, "")
	if err != nil || latest == "" {
		return v, nil
	}
	v.LatestVersion = latest
	v.NewVersionAvailable = latest != inst.Version
	return v, nil
}
