// PostgreSQL projection of scaffold run state (M8 scaffolding, plan
// §4/§10): run records plus their resumable step sub-resources. Same
// store conventions as the tenant zone factory: a stateless Store whose
// methods accept a db.Querier (pool or in-flight transaction).
package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrRunNotFound is returned for unknown (or foreign-org) runs.
var ErrRunNotFound = errors.New("scaffold: run not found")

// ErrIdempotencyConflict is returned by CreateRun when the idempotency
// unique index rejects the insert; the service re-reads and returns the
// existing run instead of failing.
var ErrIdempotencyConflict = errors.New("scaffold: idempotency key conflict")

// ErrInvalidState is returned for transitions a run's phase does not allow
// (e.g. cancelling a terminal run).
var ErrInvalidState = errors.New("scaffold: run in invalid state")

// Store persists scaffold runs and their steps.
type Store struct{}

// NewStore returns the scaffold run store.
func NewStore() *Store { return &Store{} }

const runCols = `id, org_id, template_item_id, template_version, display_name, values, phase,
	error, outputs, idempotency_key, created_by, created_at, updated_at, cancelled_at`

func scanRun(row interface{ Scan(...any) error }) (*types.ScaffoldRun, error) {
	var r types.ScaffoldRun
	var key *string
	err := row.Scan(&r.ID, &r.OrgID, &r.TemplateItemID, &r.TemplateVersion, &r.DisplayName,
		&r.Values, &r.Phase, &r.Error, &r.Outputs, &key, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt,
		&r.CancelledAt)
	if err != nil {
		return nil, err
	}
	if key != nil {
		r.IdempotencyKey = *key
	}
	return &r, nil
}

// CreateRun inserts a run and its initial step rows. A conflict on the
// (org_id, idempotency_key) partial unique index surfaces as
// ErrIdempotencyConflict — never as a generic constraint error.
func (s *Store) CreateRun(ctx context.Context, q db.Querier, r *types.ScaffoldRun, steps []types.ScaffoldRunStep) error {
	values := r.Values
	if len(values) == 0 {
		values = json.RawMessage(`{}`)
	}
	outputs := r.Outputs
	if len(outputs) == 0 {
		outputs = json.RawMessage(`{}`)
	}
	var key *string
	if r.IdempotencyKey != "" {
		key = &r.IdempotencyKey
	}
	const sql = `INSERT INTO scaffold_runs (id, org_id, template_item_id, template_version,
	             display_name, values, phase, error, outputs, idempotency_key, created_by)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING ` + runCols
	out, err := scanRun(q.QueryRow(ctx, sql, r.ID, r.OrgID, r.TemplateItemID, r.TemplateVersion,
		r.DisplayName, values, r.Phase, r.Error, outputs, key, r.CreatedBy))
	if isIdempotencyUniqueViolation(err) {
		return ErrIdempotencyConflict
	}
	if err != nil {
		return err
	}
	*r = *out
	for i := range steps {
		st := &steps[i]
		if st.State == "" {
			st.State = types.ScaffoldStepPending
		}
		result := st.Result
		if len(result) == 0 {
			result = json.RawMessage(`{}`)
		}
		const stepSQL = `INSERT INTO scaffold_run_steps (run_id, name, state, attempts, max_attempts, error, result)
		                 VALUES ($1,$2,$3,$4,$5,$6,$7)`
		if _, err := q.Exec(ctx, stepSQL, st.RunID, st.Name, st.State, st.Attempts, st.MaxAttempts, st.Error, result); err != nil {
			return err
		}
	}
	return nil
}

// GetRun loads one run by ID, scoped to the owning org (cross-org reads
// look like absence).
func (s *Store) GetRun(ctx context.Context, q db.Querier, orgID, id string) (*types.ScaffoldRun, error) {
	const sql = `SELECT ` + runCols + ` FROM scaffold_runs WHERE id = $1 AND org_id = $2`
	r, err := scanRun(q.QueryRow(ctx, sql, id, orgID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRunNotFound
	}
	return r, err
}

// GetRunByIdempotencyKey returns the run previously created with a derived
// or client-supplied idempotency key.
func (s *Store) GetRunByIdempotencyKey(ctx context.Context, q db.Querier, orgID, key string) (*types.ScaffoldRun, error) {
	const sql = `SELECT ` + runCols + ` FROM scaffold_runs WHERE org_id = $1 AND idempotency_key = $2`
	r, err := scanRun(q.QueryRow(ctx, sql, orgID, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRunNotFound
	}
	return r, err
}

// ListRuns returns an org's runs, newest first.
func (s *Store) ListRuns(ctx context.Context, q db.Querier, orgID string) ([]types.ScaffoldRun, error) {
	const sql = `SELECT ` + runCols + ` FROM scaffold_runs WHERE org_id = $1 ORDER BY created_at DESC`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.ScaffoldRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// ClaimNextRunnable locks and returns the oldest run the reconcile loop
// should drive (non-terminal phase, not cancelled). Must be called inside
// an open transaction so the SKIP LOCKED row lock is held while the runner
// works. Returns (nil, nil) when nothing is runnable.
//
// Backoff (plan Decision 4): a run whose latest failed step is still
// inside its retry window — backoff * 2^(attempts-1) since the failure —
// is skipped. Exponential in attempts, naturally capped by MaxAttempts; no
// schema change (uses updated_at/attempts).
func (s *Store) ClaimNextRunnable(ctx context.Context, q db.Querier, backoff time.Duration) (*types.ScaffoldRun, error) {
	if backoff <= 0 {
		backoff = 30 * time.Second
	}
	const sql = `SELECT ` + runCols + ` FROM scaffold_runs r
	             WHERE phase IN ('pending','rendering','creating-repo','creating-pipeline','registering-catalog','binding-rbac')
	               AND cancelled_at IS NULL
	               AND NOT EXISTS (
	                 SELECT 1 FROM scaffold_run_steps st
	                 WHERE st.run_id = r.id AND st.state = 'failed'
	                   AND st.updated_at + (make_interval(secs => $1::float8) * power(2, greatest(st.attempts - 1, 0))) > now()
	               )
	             ORDER BY created_at LIMIT 1 FOR UPDATE OF r SKIP LOCKED`
	r, err := scanRun(q.QueryRow(ctx, sql, backoff.Seconds()))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// ClaimNextCancelled locks and returns the oldest run that was cancelled
// but never settled to a terminal phase (e.g. cancelled while idle), so
// the reconcile loop can finalize it. Same TX/lock contract as
// ClaimNextRunnable. Returns (nil, nil) when none is pending.
func (s *Store) ClaimNextCancelled(ctx context.Context, q db.Querier) (*types.ScaffoldRun, error) {
	const sql = `SELECT ` + runCols + ` FROM scaffold_runs
	             WHERE cancelled_at IS NOT NULL AND phase NOT IN ('completed','failed')
	             ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED`
	r, err := scanRun(q.QueryRow(ctx, sql))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// ListSteps returns a run's steps in phase execution order.
func (s *Store) ListSteps(ctx context.Context, q db.Querier, runID string) ([]types.ScaffoldRunStep, error) {
	const sql = `SELECT run_id, name, state, attempts, max_attempts, error, result, updated_at
	             FROM scaffold_run_steps WHERE run_id = $1
	             ORDER BY array_position($2::text[], name)`
	rows, err := q.Query(ctx, sql, runID, stepNames)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.ScaffoldRunStep
	for rows.Next() {
		var st types.ScaffoldRunStep
		if err := rows.Scan(&st.RunID, &st.Name, &st.State, &st.Attempts, &st.MaxAttempts, &st.Error, &st.Result, &st.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// UpdateStep persists one step transition (idempotent by run+step).
func (s *Store) UpdateStep(ctx context.Context, q db.Querier, st *types.ScaffoldRunStep) error {
	result := st.Result
	if len(result) == 0 {
		result = json.RawMessage(`{}`)
	}
	const sql = `INSERT INTO scaffold_run_steps (run_id, name, state, attempts, max_attempts, error, result, updated_at)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,now())
	             ON CONFLICT (run_id, name) DO UPDATE SET
	               state = EXCLUDED.state, attempts = EXCLUDED.attempts,
	               error = EXCLUDED.error, result = EXCLUDED.result, updated_at = now()`
	_, err := q.Exec(ctx, sql, st.RunID, st.Name, st.State, st.Attempts, st.MaxAttempts, st.Error, result)
	return err
}

// UpdateRunPhase persists the run's phase/error (and outputs when non-nil)
// after step transitions.
func (s *Store) UpdateRunPhase(ctx context.Context, q db.Querier, id string, phase types.ScaffoldPhase, errMsg string, outputs json.RawMessage) error {
	const sql = `UPDATE scaffold_runs SET phase=$2, error=$3, outputs=COALESCE($4, outputs), updated_at=now()
	             WHERE id=$1`
	tag, err := q.Exec(ctx, sql, id, phase, errMsg, outputs)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRunNotFound
	}
	return nil
}

// ResetForRetry resumes a failed run from its first non-completed step
// (M8.W6): phase → the given next phase, error/cancelled_at cleared,
// outputs replaced (the caller drops the approval hold), and every
// non-completed step reset to pending with a fresh attempt budget. Must be
// called inside an open transaction. Returns ErrInvalidState when the run
// is not failed.
func (s *Store) ResetForRetry(ctx context.Context, q db.Querier, id string, next types.ScaffoldPhase, outputs json.RawMessage) error {
	const runSQL = `UPDATE scaffold_runs SET phase=$2, error='', outputs=$3, cancelled_at=NULL, updated_at=now()
	             WHERE id=$1 AND phase='failed'`
	tag, err := q.Exec(ctx, runSQL, id, next, outputs)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidState
	}
	const stepsSQL = `UPDATE scaffold_run_steps SET state='pending', attempts=0, error='', updated_at=now()
	             WHERE run_id=$1 AND state != 'completed'`
	_, err = q.Exec(ctx, stepsSQL, id)
	return err
}

// DeleteTerminalRuns reaps completed/failed runs whose last update is
// older than cutoff (M8.W6 run retention, INARI_SCAFFOLD_RUN_TTL). Steps
// cascade with the run row. Returns the number of runs deleted.
func (s *Store) DeleteTerminalRuns(ctx context.Context, q db.Querier, cutoff time.Time) (int64, error) {
	const sql = `DELETE FROM scaffold_runs WHERE phase IN ('completed','failed') AND updated_at < $1`
	tag, err := q.Exec(ctx, sql, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// SetCancelled raises the cooperative cancel flag. Only non-terminal runs
// can be cancelled; the reconcile loop (W3) observes cancelled_at before
// starting each step.
func (s *Store) SetCancelled(ctx context.Context, q db.Querier, id string) error {
	const sql = `UPDATE scaffold_runs SET cancelled_at=now(), updated_at=now()
	             WHERE id=$1 AND cancelled_at IS NULL AND phase NOT IN ('completed','failed')`
	tag, err := q.Exec(ctx, sql, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidState
	}
	return nil
}

// isIdempotencyUniqueViolation reports whether err is the unique violation
// of scaffold_runs_idempotency_idx specifically — a PK collision on id
// must surface as-is, not be misreported as a replay.
func isIdempotencyUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "scaffold_runs_idempotency_idx"
}
