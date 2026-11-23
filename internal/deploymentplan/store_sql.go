package deploymentplan

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type SQLStore struct{ db *db.DB }

func NewSQLStore(d *db.DB) *SQLStore { return &SQLStore{db: d} }

func planJSON(plan *Plan) ([]byte, error) { return json.Marshal(plan) }

func companionJSON(companion *Companion) ([]byte, error) { return json.Marshal(companion) }

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func idempotencyUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "deployment_plans_org_id_requester_idempotency_key_key"
}

func (s *SQLStore) CreatePlan(ctx context.Context, plan *Plan) error {
	raw, err := planJSON(plan)
	if err != nil {
		return err
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO deployment_plans
			(id, org_id, requester, idempotency_key, operation, source_kind, app_instance_id, scaffold_run_id, app_cluster_id,
			 app_version, app_ref, app_digest, pack_item_id, pack_version, pack_digest, pack_render_contract,
			 capability_digest, plan_fingerprint, state, gate_state, plan_document, error_code, error_message, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
			plan.ID, plan.OrgID, plan.Requester, plan.IdempotencyKey, plan.Operation, plan.Source.Kind, nullable(plan.AppInstanceID), nullable(plan.ScaffoldRunID), plan.AppClusterID,
			plan.App.Version, plan.App.Ref, plan.App.Digest, packField(plan, "item"), packField(plan, "version"), packField(plan, "digest"), packField(plan, "contract"),
			plan.CapabilityDigest, plan.PlanFingerprint, plan.State, mustJSON(plan.Gate), raw, plan.ErrorCode, plan.ErrorMessage, plan.CreatedAt, plan.UpdatedAt)
		if err != nil {
			if idempotencyUniqueViolation(err) {
				return ErrIdempotencyConflict
			}
			return err
		}
		return s.insertCompanionForOrg(ctx, tx, plan.Companion, plan.OrgID)
	})
}

func (s *SQLStore) insertCompanionForOrg(ctx context.Context, q db.Querier, companion *Companion, orgID string) error {
	if companion == nil {
		return nil
	}
	raw, err := companionJSON(companion)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO observability_companions
		(id, plan_id, org_id, app_instance_id, scaffold_run_id, companion_instance_id, target_id, target_revision,
		 target_cluster_id, target_selection, app_source_digest, app_revision, pack_item_id, pack_version, pack_digest,
		 pack_render_contract, capability_digest, state, generation, reason, companion_document, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
		ON CONFLICT (id) DO UPDATE SET app_instance_id=EXCLUDED.app_instance_id, scaffold_run_id=EXCLUDED.scaffold_run_id,
		 companion_instance_id=EXCLUDED.companion_instance_id, target_id=EXCLUDED.target_id, target_revision=EXCLUDED.target_revision,
		 target_cluster_id=EXCLUDED.target_cluster_id, target_selection=EXCLUDED.target_selection, app_revision=EXCLUDED.app_revision,
		 state=EXCLUDED.state, generation=EXCLUDED.generation, reason=EXCLUDED.reason, companion_document=EXCLUDED.companion_document,
		 updated_at=EXCLUDED.updated_at`,
		companion.ID, companion.PlanID, orgID, nullable(companion.AppInstanceID), nullable(companion.ScaffoldRunID), nullable(companion.CompanionInstanceID), nullable(companion.TargetID), companion.TargetRevision,
		companion.TargetClusterID, companion.TargetSelection, companion.AppSourceDigest, companion.AppRevision, companion.Pack.ItemID, companion.Pack.Version, companion.Pack.Digest,
		companion.Pack.RenderContract, companion.CapabilityDigest, companion.State, companion.Generation, companion.Reason, raw, companion.CreatedAt, companion.UpdatedAt)
	return err
}

func packField(plan *Plan, field string) string {
	if plan.Observability.Pack == nil {
		return ""
	}
	switch field {
	case "item":
		return plan.Observability.Pack.ItemID
	case "version":
		return plan.Observability.Pack.Version
	case "digest":
		return plan.Observability.Pack.Digest
	case "contract":
		return plan.Observability.Pack.RenderContract
	}
	return ""
}

func mustJSON(value any) []byte { raw, _ := json.Marshal(value); return raw }

func (s *SQLStore) UpdatePlan(ctx context.Context, plan *Plan) error {
	raw, err := planJSON(plan)
	if err != nil {
		return err
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE deployment_plans SET app_instance_id=$2, scaffold_run_id=$3, app_cluster_id=$4,
			state=$5, plan_document=$6, error_code=$7, error_message=$8, updated_at=$9 WHERE id=$1 AND org_id=$10`,
			plan.ID, nullable(plan.AppInstanceID), nullable(plan.ScaffoldRunID), plan.AppClusterID, plan.State, raw, plan.ErrorCode, plan.ErrorMessage, plan.UpdatedAt, plan.OrgID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrPlanNotFound
		}
		return s.insertCompanionForOrg(ctx, tx, plan.Companion, plan.OrgID)
	})
}

func scanPlan(row pgx.Row) (*Plan, error) {
	var raw []byte
	var requester, key string
	if err := row.Scan(&raw, &requester, &key); err != nil {
		return nil, err
	}
	var plan Plan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return nil, err
	}
	plan.Requester, plan.IdempotencyKey = requester, key
	return &plan, nil
}

func (s *SQLStore) getPlanTx(ctx context.Context, q db.Querier, query string, args ...any) (*Plan, error) {
	plan, err := scanPlan(q.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPlanNotFound
	}
	return plan, err
}

func (s *SQLStore) getPlan(ctx context.Context, query string, args ...any) (*Plan, error) {
	return s.getPlanTx(ctx, s.db.Pool, query, args...)
}

func (s *SQLStore) GetPlan(ctx context.Context, orgID, id string) (*Plan, error) {
	return s.getPlan(ctx, `SELECT plan_document, requester, idempotency_key FROM deployment_plans WHERE org_id=$1 AND id=$2`, orgID, id)
}
func (s *SQLStore) GetPlanByIdempotency(ctx context.Context, orgID, requester, key string) (*Plan, error) {
	return s.getPlan(ctx, `SELECT plan_document, requester, idempotency_key FROM deployment_plans WHERE org_id=$1 AND requester=$2 AND idempotency_key=$3`, orgID, requester, key)
}
func (s *SQLStore) LatestPlanForInstance(ctx context.Context, orgID, instanceID string) (*Plan, error) {
	return s.getPlan(ctx, `SELECT plan_document, requester, idempotency_key FROM deployment_plans WHERE org_id=$1 AND app_instance_id=$2 ORDER BY updated_at DESC LIMIT 1`, orgID, instanceID)
}

func scanCompanion(row pgx.Row) (*Companion, error) {
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		return nil, err
	}
	var companion Companion
	if err := json.Unmarshal(raw, &companion); err != nil {
		return nil, err
	}
	return &companion, nil
}
func (s *SQLStore) getCompanionTx(ctx context.Context, q db.Querier, orgID, id string) (*Companion, error) {
	companion, err := scanCompanion(q.QueryRow(ctx, `SELECT companion_document FROM observability_companions WHERE org_id=$1 AND id=$2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCompanionNotFound
	}
	return companion, err
}

func (s *SQLStore) GetCompanion(ctx context.Context, orgID, id string) (*Companion, error) {
	return s.getCompanionTx(ctx, s.db.Pool, orgID, id)
}
func (s *SQLStore) LatestCompanionForInstance(ctx context.Context, orgID, instanceID string) (*Companion, error) {
	companion, err := scanCompanion(s.db.Pool.QueryRow(ctx, `SELECT companion_document FROM observability_companions WHERE org_id=$1 AND app_instance_id=$2 ORDER BY updated_at DESC LIMIT 1`, orgID, instanceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCompanionNotFound
	}
	return companion, err
}

func (s *SQLStore) saveVerificationTx(ctx context.Context, q db.Querier, orgID string, companion *Companion, result *observability.VerificationResult, expectedVerification string) (bool, error) {
	if companion == nil || result == nil {
		return false, errors.New("companion and verification result are required")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return false, err
	}
	checks, err := json.Marshal(result.Checks)
	if err != nil {
		return false, err
	}
	companionRaw, err := companionJSON(companion)
	if err != nil {
		return false, err
	}
	tag, err := q.Exec(ctx, `INSERT INTO observability_verification_results
		(companion_id, generation, run_id, attempt, suite_digest, suite_profile, target_revision, app_revision, pack_digest,
		 capability_digest, result, checks, result_document, observed_at, expires_at, received_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (companion_id, generation, run_id, attempt, suite_digest) DO NOTHING`,
		companion.ID, result.Companion.Generation, result.Run.ID, result.Run.Attempt, result.Suite.Digest, result.Suite.Profile,
		result.Target.Revision, result.App.Revision, result.Pack.Digest, result.CapabilityDigest, result.Result, checks, raw,
		result.Run.FinishedAt, result.ExpiresAt, time.Now())
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	tag, err = q.Exec(ctx, `UPDATE observability_companions SET state=$2, reason=$3, companion_document=$4,
		latest_verification_id=$5, updated_at=$6
		WHERE id=$1 AND org_id=$7 AND generation=$8 AND latest_verification_id=$9`,
		companion.ID, companion.State, companion.Reason, companionRaw, verificationToken(result), companion.UpdatedAt,
		orgID, companion.Generation, expectedVerification)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, ErrPlanConflict
	}
	return true, nil
}

func (s *SQLStore) SaveVerification(ctx context.Context, orgID string, companion *Companion, result *observability.VerificationResult, expectedVerification string) (applied bool, err error) {
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		var applyErr error
		applied, applyErr = s.saveVerificationTx(ctx, tx, orgID, companion, result, expectedVerification)
		return applyErr
	})
	return applied, err
}
