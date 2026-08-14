// Package capabilities persists agent-reported capability-update events as
// versioned Capability records (plan §5.9) — the projection the M2 Catalog
// Service reads. Ingest is idempotent: replays of the same update converge.
package capabilities

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Store is the PostgreSQL projection of discovered capabilities.
type Store struct{}

func NewStore() *Store { return &Store{} }

func (s *Store) Upsert(ctx context.Context, q db.Querier, clusterID string, item types.CapabilityItem) error {
	mode := item.ManagementMode
	if mode == "" {
		mode = types.ManagementModeObserveOnly
	}
	const sql = `INSERT INTO capabilities (cluster_id, kind, name, "group", version, schema, ui_hints, management_mode)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	             ON CONFLICT (cluster_id, kind, "group", name, version) DO UPDATE SET
	               schema = EXCLUDED.schema,
	               ui_hints = EXCLUDED.ui_hints,
	               management_mode = EXCLUDED.management_mode,
	               last_seen_at = now(),
	               deleted_at = NULL`
	_, err := q.Exec(ctx, sql, clusterID, item.Kind, item.Name, item.Group, item.Version,
		nullJSON(item.Schema), nullJSON(item.UIHints), mode)
	return err
}

func (s *Store) SoftDelete(ctx context.Context, q db.Querier, clusterID string, item types.CapabilityItem) (bool, error) {
	const sql = `UPDATE capabilities SET deleted_at = now()
	             WHERE cluster_id = $1 AND kind = $2 AND "group" = $3 AND name = $4 AND version = $5
	               AND deleted_at IS NULL`
	tag, err := q.Exec(ctx, sql, clusterID, item.Kind, item.Group, item.Name, item.Version)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// SoftDeleteMissing marks every live capability not in keep as deleted
// (full-sync semantics: the snapshot is authoritative).
func (s *Store) SoftDeleteMissing(ctx context.Context, q db.Querier, clusterID string, keep []types.CapabilityItem) (int, error) {
	const sel = `SELECT kind, "group", name, version FROM capabilities
	             WHERE cluster_id = $1 AND deleted_at IS NULL`
	rows, err := q.Query(ctx, sel, clusterID)
	if err != nil {
		return 0, err
	}
	type key struct{ kind, group, name, version string }
	keepSet := map[key]bool{}
	for _, it := range keep {
		keepSet[key{string(it.Kind), it.Group, it.Name, it.Version}] = true
	}
	var stale []key
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.kind, &k.group, &k.name, &k.version); err != nil {
			rows.Close()
			return 0, err
		}
		if !keepSet[k] {
			stale = append(stale, k)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, k := range stale {
		const del = `UPDATE capabilities SET deleted_at = now()
		             WHERE cluster_id = $1 AND kind = $2 AND "group" = $3 AND name = $4 AND version = $5
		               AND deleted_at IS NULL`
		if _, err := q.Exec(ctx, del, clusterID, k.kind, k.group, k.name, k.version); err != nil {
			return 0, err
		}
	}
	return len(stale), nil
}

// List returns the live capabilities of a cluster (M2 Catalog read model).
func (s *Store) List(ctx context.Context, q db.Querier, clusterID string) ([]types.Capability, error) {
	const sql = `SELECT id, cluster_id, kind, name, "group", version, schema, ui_hints, management_mode,
	                    first_seen_at, last_seen_at, deleted_at
	             FROM capabilities WHERE cluster_id = $1 AND deleted_at IS NULL
	             ORDER BY kind, "group", name, version`
	rows, err := q.Query(ctx, sql, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Capability
	for rows.Next() {
		var c types.Capability
		if err := rows.Scan(&c.ID, &c.ClusterID, &c.Kind, &c.Name, &c.Group, &c.Version,
			&c.Schema, &c.UIHints, &c.ManagementMode, &c.FirstSeenAt, &c.LastSeenAt, &c.DeletedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func nullJSON(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

// Service ingests capability updates with audit + outbox in one TX.
type Service struct {
	db    *db.DB
	store *Store
	audit *audit.Store
}

func NewService(d *db.DB, store *Store, auditStore *audit.Store) *Service {
	return &Service{db: d, store: store, audit: auditStore}
}

// Ingest persists one capability-update for a cluster: upserts, deletes,
// full-sync reconciliation, checksum bookkeeping, audit + outbox.
func (s *Service) Ingest(ctx context.Context, orgID, clusterID string, upd types.CapabilityIngest) error {
	var upserted, deleted int
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		var upserts []types.CapabilityItem
		for _, item := range upd.Items {
			switch item.Action {
			case types.CapabilityActionDelete:
				ok, err := s.store.SoftDelete(ctx, tx, clusterID, item)
				if err != nil {
					return err
				}
				if ok {
					deleted++
				}
			default: // upsert (also the zero value)
				if err := s.store.Upsert(ctx, tx, clusterID, item); err != nil {
					return err
				}
				upserted++
				upserts = append(upserts, item)
			}
		}
		if upd.FullSync {
			n, err := s.store.SoftDeleteMissing(ctx, tx, clusterID, upserts)
			if err != nil {
				return err
			}
			deleted += n
		}
		if upd.StateChecksum != "" {
			const sql = `UPDATE clusters SET capability_checksum = $2, last_seen_at = now() WHERE id = $1`
			if _, err := tx.Exec(ctx, sql, clusterID, upd.StateChecksum); err != nil {
				return err
			}
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: "agent:" + clusterID, Action: "capabilities.ingested",
			ObjectType: "cluster", ObjectID: clusterID,
			Payload: json.RawMessage(fmt.Sprintf(`{"upserted":%d,"deleted":%d,"fullSync":%t}`, upserted, deleted, upd.FullSync)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventCapabilitiesIngested, types.CapabilitiesIngestedPayload{
			OrgID: orgID, ClusterID: clusterID,
			Upserted: upserted, Deleted: deleted,
			FullSync: upd.FullSync, StateChecksum: upd.StateChecksum,
		})
	})
	if err != nil {
		return fmt.Errorf("capabilities: ingest: %w", err)
	}
	return nil
}

// List returns the live capabilities of a cluster.
func (s *Service) List(ctx context.Context, clusterID string) ([]types.Capability, error) {
	return s.store.List(ctx, s.db.Pool, clusterID)
}
