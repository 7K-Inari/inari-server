// Drift detection (plan §5.11): continuous diff of desired state
// (control-plane intent + tenant Git) vs agent-reported state. v1 is
// report-only: drift surfaces as DriftEvent rows + outbox events (driving
// API reads and notifications); it never triggers remediation.
package fleetmanager

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ReportDrift records one detected divergence, emitting audit + outbox
// (EventDriftDetected drives notifications and the FGA tuple). Idempotent
// per (cluster, kind, resource, reported hash) while an open event exists.
// Reports whether a new event was created.
func (s *Service) ReportDrift(ctx context.Context, d *types.DriftEvent) (bool, error) {
	if d.OrgID == "" || d.ClusterID == "" || d.Kind == "" {
		return false, fmt.Errorf("%w: orgID, clusterID and kind are required", ErrInvalidInput)
	}
	open, err := s.store.hasOpenDrift(ctx, s.db.Pool, d.ClusterID, d.Kind, d.ResourceRef, d.ReportedHash)
	if err != nil {
		return false, err
	}
	if open {
		return false, nil
	}
	if d.ID == "" {
		d.ID = "drift:" + newUUID()
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.insertDrift(ctx, tx, d); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: d.OrgID, Actor: "system:fleetmanager", Action: "drift.detected",
			ObjectType: "drift_event", ObjectID: d.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, d.OrgID, types.EventDriftDetected, types.DriftPayload{
			OrgID: d.OrgID, DriftID: d.ID, ClusterID: d.ClusterID, Kind: d.Kind, ResourceRef: d.ResourceRef,
		})
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

// ResolveDrift marks an open event resolved (audit + outbox), e.g. when the
// resource reports in-sync again. No-op when already resolved.
func (s *Service) ResolveDrift(ctx context.Context, d *types.DriftEvent) error {
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		ok, err := s.store.resolveDrift(ctx, tx, d.ID)
		if err != nil {
			return err
		}
		if !ok {
			return nil // already resolved
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: d.OrgID, Actor: "system:fleetmanager", Action: "drift.resolved",
			ObjectType: "drift_event", ObjectID: d.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, d.OrgID, types.EventDriftResolved, types.DriftPayload{
			OrgID: d.OrgID, DriftID: d.ID, ClusterID: d.ClusterID, Kind: d.Kind, ResourceRef: d.ResourceRef,
		})
	})
}

// ListDrift returns drift events for an org, optionally filtered by cluster
// and status.
func (s *Service) ListDrift(ctx context.Context, orgID, clusterID, status string) ([]types.DriftEvent, error) {
	return s.store.listDrift(ctx, s.db.Pool, orgID, clusterID, status)
}

// outOfSyncInstance is one agent-reported desired-vs-live divergence.
type outOfSyncInstance struct {
	OrgID      string
	ClusterID  string
	InstanceID string
	Kind       string
	Name       string
	Namespace  string
	SyncState  string
}

// listOutOfSyncInstances reads the inventory projection for instances whose
// agent-reported sync state diverged from desired state.
func (s *Store) listOutOfSyncInstances(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) ([]outOfSyncInstance, error) {
	const sql = `SELECT org_id, cluster_id, id,
	                    COALESCE(resource_ref->>'kind', ''), COALESCE(resource_ref->>'name', ''),
	                    COALESCE(resource_ref->>'namespace', ''), sync_state
	             FROM resource_instances
	             WHERE sync_state <> '' AND sync_state NOT IN ('Synced', 'synced')`
	rows, err := q.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []outOfSyncInstance
	for rows.Next() {
		var i outOfSyncInstance
		if err := rows.Scan(&i.OrgID, &i.ClusterID, &i.InstanceID, &i.Kind, &i.Name, &i.Namespace, &i.SyncState); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// DriftSweep compares reported sync state against desired intent once,
// reports new drift, and resolves open events whose resource is back in
// sync (or whose reported state changed). Returns the number of new events.
func (s *Service) DriftSweep(ctx context.Context) (int, error) {
	diverged, err := s.store.listOutOfSyncInstances(ctx, s.db.Pool)
	if err != nil {
		return 0, err
	}
	current := map[string]string{} // cluster|kind|ref → reported state
	n := 0
	for _, i := range diverged {
		ref := i.Kind + "/" + i.Name
		if i.Namespace != "" {
			ref = i.Kind + "/" + i.Namespace + "/" + i.Name
		}
		current[i.ClusterID+"|"+types.DriftKindInstanceSpec+"|"+ref] = i.SyncState
		created, err := s.ReportDrift(ctx, &types.DriftEvent{
			OrgID: i.OrgID, ClusterID: i.ClusterID, Kind: types.DriftKindInstanceSpec,
			ResourceRef: ref, ReportedHash: i.SyncState,
			Detail: fmt.Sprintf("instance %s reported sync state %s", i.InstanceID, i.SyncState),
		})
		if err != nil {
			return n, err
		}
		if created {
			n++
		}
	}
	// Resolution pass: open instance-spec events that no longer match the
	// currently diverged set are stale (resource back in sync, or reported
	// state changed and a fresh event was just opened).
	open, err := s.store.listOpenDrift(ctx, s.db.Pool)
	if err != nil {
		return n, err
	}
	for i := range open {
		d := &open[i]
		if d.Kind != types.DriftKindInstanceSpec {
			continue // other kinds are reported by their own detectors
		}
		if current[d.ClusterID+"|"+d.Kind+"|"+d.ResourceRef] == d.ReportedHash {
			continue // still diverged as reported
		}
		if err := s.ResolveDrift(ctx, d); err != nil {
			return n, err
		}
	}
	return n, nil
}

// RunDriftLoop runs DriftSweep on an interval until ctx is cancelled.
func (s *Service) RunDriftLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if _, err := s.DriftSweep(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("drift sweep failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
