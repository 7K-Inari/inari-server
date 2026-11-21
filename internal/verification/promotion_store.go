package verification

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/jackc/pgx/v5"
)

func (s *Store) PutPromotionPolicy(ctx context.Context, q db.Querier, policy *PromotionPolicy) error {
	spec, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE verification_promotion_policies SET current=false, updated_at=now() WHERE target_instance_id=$1 AND current`, policy.TargetInstanceID); err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO verification_promotion_policies
		(id, org_id, target_instance_id, source_instance_id, required_suite_digest, required_profile, policy_revision, policy_spec, current, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,$9,$10)`, policy.ID, policy.OrgID, policy.TargetInstanceID, policy.SourceInstanceID,
		policy.RequiredSuiteDigest, policy.RequiredProfile, policy.Revision, spec, policy.CreatedAt, policy.UpdatedAt)
	return err
}

func (s *Store) GetPromotionPolicy(ctx context.Context, q db.Querier, orgID, targetInstanceID string) (*PromotionPolicy, error) {
	var policy PromotionPolicy
	var spec json.RawMessage
	err := q.QueryRow(ctx, `SELECT policy_spec FROM verification_promotion_policies WHERE org_id=$1 AND target_instance_id=$2 AND current`, orgID, targetInstanceID).Scan(&spec)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(spec, &policy); err != nil {
		return nil, err
	}
	policy.Current = true
	return &policy, nil
}

func (s *Store) InstanceEnvironment(ctx context.Context, q db.Querier, orgID, instanceID string) (string, error) {
	var environment string
	err := q.QueryRow(ctx, `SELECT c.labels->>'inari.dev/environment' FROM resource_instances i JOIN clusters c ON c.id=i.cluster_id WHERE i.org_id=$1 AND i.id=$2`, orgID, instanceID).Scan(&environment)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return environment, err
}

func validatePromotionPolicy(policy *PromotionPolicy) error {
	if policy == nil || policy.OrgID == "" || policy.TargetInstanceID == "" || policy.SourceInstanceID == "" || policy.TargetInstanceID == policy.SourceInstanceID {
		return errors.New("promotion policy requires distinct source and target instances")
	}
	if policy.Revision < 1 || !verificationDigestPattern.MatchString(policy.RequiredSuiteDigest) || policy.RequiredProfile != ProfileStage {
		return errors.New("promotion policy requires a positive revision, exact suite digest, and stage source profile")
	}
	if age, err := time.ParseDuration(policy.MaxEvidenceAge); err != nil || age <= 0 || age > 30*24*time.Hour {
		return errors.New("maxEvidenceAge must be a positive duration up to 720h")
	}
	seen := map[string]bool{}
	for _, team := range policy.ApproverTeamIDs {
		if team == "" || seen[team] {
			return errors.New("approverTeamIds must be nonempty and unique")
		}
		seen[team] = true
	}
	return nil
}
