// Fleet persistence: rollouts, per-cluster rollout targets, agent channels,
// drift events. Store methods take a db.Querier so services can commit
// business rows + audit + outbox in one transaction.
package fleetmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Store persists fleet manager rows.
type Store struct{}

func NewStore() *Store { return &Store{} }

const rolloutCols = `id, org_id, name, kind, target_ref, desired_version, stages, state, current_stage, gate_context, created_by, created_at, updated_at`

func scanRollout(row interface{ Scan(...any) error }) (*types.Rollout, error) {
	var r types.Rollout
	var stages, gateCtx []byte
	err := row.Scan(&r.ID, &r.OrgID, &r.Name, &r.Kind, &r.TargetRef, &r.DesiredVersion,
		&stages, &r.State, &r.CurrentStage, &gateCtx, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(stages, &r.Stages); err != nil {
		return nil, fmt.Errorf("fleetmanager: rollout stages: %w", err)
	}
	if len(gateCtx) > 0 {
		var gc types.RolloutGateContext
		if err := json.Unmarshal(gateCtx, &gc); err != nil {
			return nil, fmt.Errorf("fleetmanager: rollout gate context: %w", err)
		}
		r.GateContext = &gc
	}
	return &r, nil
}

func (s *Store) createRollout(ctx context.Context, q db.Querier, r *types.Rollout) error {
	stages, err := json.Marshal(r.Stages)
	if err != nil {
		return err
	}
	const sql = `INSERT INTO rollouts (id, org_id, name, kind, target_ref, desired_version, stages, created_by)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	             RETURNING state, current_stage, created_at, updated_at`
	return q.QueryRow(ctx, sql, r.ID, r.OrgID, r.Name, r.Kind, r.TargetRef, r.DesiredVersion, stages, r.CreatedBy).
		Scan(&r.State, &r.CurrentStage, &r.CreatedAt, &r.UpdatedAt)
}

func (s *Store) getRollout(ctx context.Context, q db.Querier, id string) (*types.Rollout, error) {
	r, err := scanRollout(q.QueryRow(ctx, `SELECT `+rolloutCols+` FROM rollouts WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func (s *Store) listRollouts(ctx context.Context, q db.Querier, orgID string) ([]types.Rollout, error) {
	rows, err := q.Query(ctx, `SELECT `+rolloutCols+` FROM rollouts WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Rollout
	for rows.Next() {
		r, err := scanRollout(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// listActiveRollouts returns rollouts the advance loop must drive.
func (s *Store) listActiveRollouts(ctx context.Context, q db.Querier) ([]types.Rollout, error) {
	rows, err := q.Query(ctx, `SELECT `+rolloutCols+` FROM rollouts WHERE state IN ($1, $2)`,
		types.RolloutStateRunning, types.RolloutStateWaitingGate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Rollout
	for rows.Next() {
		r, err := scanRollout(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// setRolloutState CAS-updates state/stage/gate-context; returns false when
// the rollout moved concurrently (caller re-reads).
func (s *Store) setRolloutState(ctx context.Context, q db.Querier, id, wantState, state string, stage int, gateCtx *types.RolloutGateContext) (bool, error) {
	var raw []byte
	if gateCtx != nil {
		var err error
		raw, err = json.Marshal(gateCtx)
		if err != nil {
			return false, err
		}
	}
	const sql = `UPDATE rollouts SET state = $2, current_stage = $3, gate_context = $4, updated_at = now()
	             WHERE id = $1 AND state = $5`
	tag, err := q.Exec(ctx, sql, id, state, stage, raw, wantState)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// setGateApproval links a created approval request into the parked gate
// context; returns false when the rollout moved concurrently (caller treats
// the approval as orphan — its decision is a no-op via gateApproved).
func (s *Store) setGateApproval(ctx context.Context, q db.Querier, rolloutID string, stage int, gate, approvalID string) (bool, error) {
	const sql = `UPDATE rollouts
	             SET gate_context = jsonb_set(gate_context, '{approvalId}', to_jsonb($4::text)), updated_at = now()
	             WHERE id = $1 AND state = $5 AND current_stage = $2
	               AND gate_context->>'gate' = $3 AND gate_context->>'approvalId' IS NULL`
	tag, err := q.Exec(ctx, sql, rolloutID, stage, gate, approvalID, types.RolloutStateWaitingGate)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) upsertTarget(ctx context.Context, q db.Querier, t *types.RolloutTarget) error {
	const sql = `INSERT INTO rollout_targets (rollout_id, cluster_id, stage, status, command_id)
	             VALUES ($1,$2,$3,$4,$5)
	             ON CONFLICT (rollout_id, cluster_id, stage) DO UPDATE
	             SET status = EXCLUDED.status, command_id = EXCLUDED.command_id, updated_at = now()`
	_, err := q.Exec(ctx, sql, t.RolloutID, t.ClusterID, t.Stage, t.Status, t.CommandID)
	return err
}

func (s *Store) listTargets(ctx context.Context, q db.Querier, rolloutID string, stage int) ([]types.RolloutTarget, error) {
	const sql = `SELECT rollout_id, cluster_id, stage, status, command_id, observed_health, updated_at
	             FROM rollout_targets WHERE rollout_id = $1 AND stage = $2 ORDER BY cluster_id`
	rows, err := q.Query(ctx, sql, rolloutID, stage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.RolloutTarget
	for rows.Next() {
		var t types.RolloutTarget
		if err := rows.Scan(&t.RolloutID, &t.ClusterID, &t.Stage, &t.Status, &t.CommandID, &t.ObservedHealth, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) setTargetStatus(ctx context.Context, q db.Querier, rolloutID, clusterID string, stage int, status, health string) error {
	const sql = `UPDATE rollout_targets SET status = $4, observed_health = $5, updated_at = now()
	             WHERE rollout_id = $1 AND cluster_id = $2 AND stage = $3`
	_, err := q.Exec(ctx, sql, rolloutID, clusterID, stage, status, health)
	return err
}

// commandStatuses reads agent_commands ack state for health gating.
func (s *Store) commandStatuses(ctx context.Context, q db.Querier, ids []string) (map[string]types.CommandStatus, error) {
	out := map[string]types.CommandStatus{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT id, status FROM agent_commands WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var st types.CommandStatus
		if err := rows.Scan(&id, &st); err != nil {
			return nil, err
		}
		out[id] = st
	}
	return out, rows.Err()
}

const channelCols = `id, org_id, cluster_set_id, channel, desired_agent_version, created_at, updated_at`

func scanChannel(row interface{ Scan(...any) error }) (*types.AgentChannel, error) {
	var c types.AgentChannel
	err := row.Scan(&c.ID, &c.OrgID, &c.ClusterSetID, &c.Channel, &c.DesiredAgentVersion, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) upsertChannel(ctx context.Context, q db.Querier, c *types.AgentChannel) error {
	const sql = `INSERT INTO agent_channels (id, org_id, cluster_set_id, channel, desired_agent_version)
	             VALUES ($1,$2,$3,$4,$5)
	             ON CONFLICT (cluster_set_id, channel) DO UPDATE
	             SET desired_agent_version = EXCLUDED.desired_agent_version, updated_at = now()
	             RETURNING created_at, updated_at`
	return q.QueryRow(ctx, sql, c.ID, c.OrgID, c.ClusterSetID, c.Channel, c.DesiredAgentVersion).
		Scan(&c.CreatedAt, &c.UpdatedAt)
}

func (s *Store) listChannels(ctx context.Context, q db.Querier, orgID string) ([]types.AgentChannel, error) {
	rows, err := q.Query(ctx, `SELECT `+channelCols+` FROM agent_channels WHERE org_id = $1 ORDER BY created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.AgentChannel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *Store) insertDrift(ctx context.Context, q db.Querier, d *types.DriftEvent) error {
	const sql = `INSERT INTO drift_events (id, org_id, cluster_id, kind, resource_ref, desired_hash, reported_hash, detail)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING detected_at`
	return q.QueryRow(ctx, sql, d.ID, d.OrgID, d.ClusterID, d.Kind, d.ResourceRef, d.DesiredHash, d.ReportedHash, d.Detail).
		Scan(&d.DetectedAt)
}

// hasOpenDrift reports whether an identical open drift event already exists
// (sweep idempotency).
func (s *Store) hasOpenDrift(ctx context.Context, q db.Querier, clusterID, kind, resourceRef, reportedHash string) (bool, error) {
	const sql = `SELECT 1 FROM drift_events
	             WHERE cluster_id = $1 AND kind = $2 AND resource_ref = $3 AND reported_hash = $4 AND status = 'open'`
	var one int
	err := q.QueryRow(ctx, sql, clusterID, kind, resourceRef, reportedHash).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func scanDriftEvent(row interface{ Scan(...any) error }) (*types.DriftEvent, error) {
	var d types.DriftEvent
	err := row.Scan(&d.ID, &d.OrgID, &d.ClusterID, &d.Kind, &d.ResourceRef,
		&d.DesiredHash, &d.ReportedHash, &d.Detail, &d.Status, &d.DetectedAt)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

const driftCols = `id, org_id, cluster_id, kind, resource_ref, desired_hash, reported_hash, detail, status, detected_at`

// listOpenDrift returns every open drift event (sweep resolution pass).
func (s *Store) listOpenDrift(ctx context.Context, q db.Querier) ([]types.DriftEvent, error) {
	rows, err := q.Query(ctx, `SELECT `+driftCols+` FROM drift_events WHERE status = 'open'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.DriftEvent
	for rows.Next() {
		d, err := scanDriftEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// resolveDrift marks an open event resolved; returns false when it was
// already resolved concurrently.
func (s *Store) resolveDrift(ctx context.Context, q db.Querier, id string) (bool, error) {
	tag, err := q.Exec(ctx, `UPDATE drift_events SET status = 'resolved' WHERE id = $1 AND status = 'open'`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) listDrift(ctx context.Context, q db.Querier, orgID, clusterID, status string) ([]types.DriftEvent, error) {
	sql := `SELECT ` + driftCols + ` FROM drift_events WHERE org_id = $1`
	args := []any{orgID}
	if clusterID != "" {
		args = append(args, clusterID)
		sql += fmt.Sprintf(` AND cluster_id = $%d`, len(args))
	}
	if status != "" {
		args = append(args, status)
		sql += fmt.Sprintf(` AND status = $%d`, len(args))
	}
	sql += ` ORDER BY detected_at DESC`
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.DriftEvent
	for rows.Next() {
		d, err := scanDriftEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}
