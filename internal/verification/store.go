package verification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/jackc/pgx/v5"
)

var ErrRunNotFound = errors.New("verification: run not found")

// Store is the PostgreSQL projection for verification policy and run state.
type Store struct{}

func NewStore() *Store { return &Store{} }

const runCols = `id, run_key, org_id, instance_id, instance_uid, app_revision, app_artifact_digest,
	suite_digest, profile, trigger, trigger_fingerprint, status, disposition, reason_code, message,
	policy_revision, grant_revision, latest_attempt, outcome, outcome_digest, expires_at, created_at, updated_at`

// InsertRun inserts a run and its first attempt. Duplicate run keys are a
// no-op; callers retrieve the existing row in the same transaction.
func (s *Store) InsertRun(ctx context.Context, q db.Querier, run *Run) (bool, error) {
	if run == nil {
		return false, errors.New("run is required")
	}
	trigger, err := json.Marshal(run.Trigger)
	if err != nil {
		return false, err
	}
	var outcome any
	if len(run.Outcome) > 0 {
		outcome = run.Outcome
	}
	const insert = `INSERT INTO verification_runs
		(id, run_key, org_id, instance_id, instance_uid, app_revision, app_artifact_digest,
		 suite_digest, profile, trigger, trigger_fingerprint, status, disposition, reason_code, message,
		 policy_revision, grant_revision, latest_attempt, outcome, outcome_digest, expires_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
		ON CONFLICT(run_key) DO NOTHING`
	tag, err := q.Exec(ctx, insert, run.ID, run.RunKey, run.OrgID, run.InstanceID, run.InstanceUID, run.AppRevision,
		run.AppArtifactDigest, run.SuiteDigest, run.Profile, trigger, run.TriggerFingerprint, run.Status, run.Disposition,
		run.ReasonCode, run.Message, run.PolicyRevision, run.GrantRevision, run.LatestAttempt, outcome,
		run.OutcomeDigest, run.ExpiresAt, run.CreatedAt, run.UpdatedAt)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	_, err = q.Exec(ctx, `INSERT INTO verification_run_attempts (run_id, attempt, state, message) VALUES ($1,$2,$3,$4)`,
		run.ID, run.LatestAttempt, run.Status, run.Message)
	if err != nil {
		return false, fmt.Errorf("insert run attempt: %w", err)
	}
	return true, nil
}

func scanRun(row pgx.Row) (*Run, error) {
	var run Run
	var trigger, outcome json.RawMessage
	err := row.Scan(&run.ID, &run.RunKey, &run.OrgID, &run.InstanceID, &run.InstanceUID, &run.AppRevision,
		&run.AppArtifactDigest, &run.SuiteDigest, &run.Profile, &trigger, &run.TriggerFingerprint, &run.Status,
		&run.Disposition, &run.ReasonCode, &run.Message, &run.PolicyRevision, &run.GrantRevision, &run.LatestAttempt,
		&outcome, &run.OutcomeDigest, &run.ExpiresAt, &run.CreatedAt, &run.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(trigger, &run.Trigger); err != nil {
		return nil, fmt.Errorf("decode run trigger: %w", err)
	}
	run.Outcome = outcome
	return &run, nil
}

func (s *Store) GetRunByKey(ctx context.Context, q db.Querier, orgID, runKey string) (*Run, error) {
	run, err := scanRun(q.QueryRow(ctx, `SELECT `+runCols+` FROM verification_runs WHERE org_id=$1 AND run_key=$2`, orgID, runKey))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRunNotFound
	}
	return run, err
}

func (s *Store) GetRun(ctx context.Context, q db.Querier, orgID, instanceID, runID string) (*Run, error) {
	run, err := scanRun(q.QueryRow(ctx, `SELECT `+runCols+` FROM verification_runs WHERE org_id=$1 AND instance_id=$2 AND id=$3`, orgID, instanceID, runID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRunNotFound
	}
	return run, err
}

func (s *Store) ListRuns(ctx context.Context, q db.Querier, orgID, instanceID string, limit int) ([]Run, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := q.Query(ctx, `SELECT `+runCols+` FROM verification_runs WHERE org_id=$1 AND instance_id=$2 ORDER BY created_at DESC LIMIT $3`, orgID, instanceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Run, 0)
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *run)
	}
	return out, rows.Err()
}

func (s *Store) CountActiveRuns(ctx context.Context, q db.Querier, instanceUID string) (int, error) {
	var count int
	err := q.QueryRow(ctx, `SELECT count(*) FROM verification_runs
		WHERE instance_uid=$1 AND status='verification_pending'
		  AND disposition NOT IN ('waiting_for_sync','blocked_external_gate','skipped_addon_unavailable','superseded','cancelled')`, instanceUID).Scan(&count)
	return count, err
}
