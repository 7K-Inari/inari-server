package verification

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/jackc/pgx/v5"
)

func (s *Store) GetRunByID(ctx context.Context, q db.Querier, orgID, runID string) (*Run, error) {
	run, err := scanRun(q.QueryRow(ctx, `SELECT `+runCols+` FROM verification_runs WHERE org_id=$1 AND id=$2`, orgID, runID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRunNotFound
	}
	return run, err
}

func (s *Store) GetPolicyRevision(ctx context.Context, q db.Querier, orgID, instanceID string, revision int64) (*VerificationPolicy, string, error) {
	var policy VerificationPolicy
	var spec json.RawMessage
	var renderFingerprint string
	err := q.QueryRow(ctx, `SELECT policy_spec, render_fingerprint FROM verification_policies WHERE org_id=$1 AND instance_id=$2 AND policy_revision=$3`, orgID, instanceID, revision).Scan(&spec, &renderFingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	if err := json.Unmarshal(spec, &policy); err != nil {
		return nil, "", err
	}
	return &policy, renderFingerprint, nil
}

type reportMutation struct {
	clusterID                            string
	status, disposition, reason, message string
	outcome                              json.RawMessage
	outcomeDigest                        string
	expiresAt, linksExpireAt             *time.Time
	startedAt, finishedAt, observedAt    *time.Time
}

func (s *Store) applyReport(ctx context.Context, q db.Querier, run *Run, report *agentv1.VerificationReport, payloadDigest string, mutation reportMutation) (bool, error) {
	tag, err := q.Exec(ctx, `INSERT INTO verification_report_receipts
		(cluster_id, workflow_uid, resource_version, run_id, attempt, payload_digest)
		VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		mutation.clusterID, report.Workflow.Uid, report.ResourceVersion, run.ID, report.Attempt, payloadDigest)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		var existingDigest string
		if err := q.QueryRow(ctx, `SELECT payload_digest FROM verification_report_receipts WHERE cluster_id=$1 AND workflow_uid=$2 AND resource_version=$3`,
			mutation.clusterID, report.Workflow.Uid, report.ResourceVersion).Scan(&existingDigest); err != nil {
			return false, err
		}
		if existingDigest != payloadDigest {
			return false, ErrConflict
		}
		return false, nil
	}
	var outcome any
	if len(mutation.outcome) > 0 {
		outcome = mutation.outcome
	}
	if _, err := q.Exec(ctx, `UPDATE verification_runs SET status=$2, disposition=$3, reason_code=$4, message=$5,
		outcome=$6, outcome_digest=$7, expires_at=$8, latest_attempt=$9, updated_at=now() WHERE id=$1`,
		run.ID, mutation.status, mutation.disposition, mutation.reason, mutation.message, outcome,
		mutation.outcomeDigest, mutation.expiresAt, report.Attempt); err != nil {
		return false, err
	}
	_, err = q.Exec(ctx, `INSERT INTO verification_run_attempts
		(run_id, attempt, workflow_name, workflow_namespace, workflow_uid, cluster_id, render_fingerprint,
		 outcome_digest, outcome, state, message, started_at, finished_at, observed_at, expires_at, links_expire_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT(run_id,attempt) DO UPDATE SET workflow_name=EXCLUDED.workflow_name,
		workflow_namespace=EXCLUDED.workflow_namespace, workflow_uid=EXCLUDED.workflow_uid, cluster_id=EXCLUDED.cluster_id,
		render_fingerprint=EXCLUDED.render_fingerprint, outcome_digest=EXCLUDED.outcome_digest, outcome=EXCLUDED.outcome,
		state=EXCLUDED.state, message=EXCLUDED.message, started_at=EXCLUDED.started_at, finished_at=EXCLUDED.finished_at,
		observed_at=EXCLUDED.observed_at, expires_at=EXCLUDED.expires_at, links_expire_at=EXCLUDED.links_expire_at`,
		run.ID, report.Attempt, report.Workflow.Name, report.Workflow.Namespace, report.Workflow.Uid, mutation.clusterID,
		report.RenderFingerprint, mutation.outcomeDigest, outcome, mutation.status, mutation.message,
		mutation.startedAt, mutation.finishedAt, mutation.observedAt, mutation.expiresAt, mutation.linksExpireAt)
	if err != nil {
		return false, err
	}
	return true, nil
}
