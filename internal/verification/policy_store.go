package verification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/jackc/pgx/v5"
)

var (
	ErrNotFound = errors.New("verification: object not found")
	ErrConflict = errors.New("verification: revision conflict")
)

const suiteReleaseCols = `id, org_id, source_id, suite_digest, descriptor, normalized_suite, workflow_template,
	content_digest, evidence_digest, source_fingerprint, eligibility, trust_tier, unsigned, legacy_exception, admitted_at`

func (s *Store) CreateSuiteRelease(ctx context.Context, q db.Querier, release *SuiteRelease) (bool, error) {
	descriptor, err := json.Marshal(release.Descriptor)
	if err != nil {
		return false, err
	}
	normalized, err := json.Marshal(release.Suite)
	if err != nil {
		return false, err
	}
	tag, err := q.Exec(ctx, `INSERT INTO verification_suite_releases
		(id, org_id, source_id, suite_digest, descriptor, normalized_suite, workflow_template, content_digest,
		 evidence_digest, source_fingerprint, eligibility, trust_tier, unsigned, legacy_exception, admitted_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(org_id,suite_digest) DO NOTHING`,
		release.ID, release.OrgID, release.SourceID, release.SuiteDigest, descriptor, normalized, release.WorkflowTemplate,
		release.ContentDigest, release.EvidenceDigest, release.SourceFingerprint, release.Eligibility,
		string(release.TrustTier), release.Unsigned, release.LegacyException, release.AdmittedAt)
	return tag.RowsAffected() == 1, err
}

func scanSuiteRelease(row pgx.Row) (*SuiteRelease, error) {
	var release SuiteRelease
	var descriptor, normalized json.RawMessage
	var trustTier string
	err := row.Scan(&release.ID, &release.OrgID, &release.SourceID, &release.SuiteDigest, &descriptor, &normalized,
		&release.WorkflowTemplate, &release.ContentDigest, &release.EvidenceDigest, &release.SourceFingerprint,
		&release.Eligibility, &trustTier, &release.Unsigned, &release.LegacyException, &release.AdmittedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(descriptor, &release.Descriptor); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(normalized, &release.Suite); err != nil {
		return nil, err
	}
	release.TrustTier = trustedsource.TrustTier(trustTier)
	return &release, nil
}

func (s *Store) GetSuiteRelease(ctx context.Context, q db.Querier, orgID, digest string) (*SuiteRelease, error) {
	release, err := scanSuiteRelease(q.QueryRow(ctx, `SELECT `+suiteReleaseCols+` FROM verification_suite_releases WHERE org_id=$1 AND suite_digest=$2`, orgID, digest))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return release, err
}

func (s *Store) GetSuiteReleaseByID(ctx context.Context, q db.Querier, orgID, id string) (*SuiteRelease, error) {
	release, err := scanSuiteRelease(q.QueryRow(ctx, `SELECT `+suiteReleaseCols+` FROM verification_suite_releases WHERE org_id=$1 AND id=$2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return release, err
}

func (s *Store) ListSuiteReleases(ctx context.Context, q db.Querier, orgID string) ([]SuiteRelease, error) {
	rows, err := q.Query(ctx, `SELECT `+suiteReleaseCols+` FROM verification_suite_releases WHERE org_id=$1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SuiteRelease, 0)
	for rows.Next() {
		release, err := scanSuiteRelease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *release)
	}
	return out, rows.Err()
}

func (s *Store) UpsertEnvironmentPolicy(ctx context.Context, q db.Querier, policy *EnvironmentPolicy) error {
	limits, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO verification_environment_policies
		(id, org_id, target_id, target_revision, environment, policy_revision, limits, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(org_id,target_id) DO UPDATE SET
		id=EXCLUDED.id, target_revision=EXCLUDED.target_revision, environment=EXCLUDED.environment,
		policy_revision=EXCLUDED.policy_revision, limits=EXCLUDED.limits, updated_at=EXCLUDED.updated_at`,
		policy.ID, policy.OrgID, policy.TargetID, policy.TargetRevision, string(policy.Environment), policy.Revision, limits, policy.CreatedAt, policy.UpdatedAt)
	return err
}

const environmentCols = `id, org_id, target_id, target_revision, environment, policy_revision, limits, created_at, updated_at`

func scanEnvironmentPolicy(row pgx.Row) (*EnvironmentPolicy, error) {
	var policy EnvironmentPolicy
	var limits json.RawMessage
	var environment string
	var id, orgID, targetID string
	var targetRevision, revision int64
	var createdAt, updatedAt time.Time
	if err := row.Scan(&id, &orgID, &targetID, &targetRevision, &environment, &revision, &limits, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(limits, &policy); err != nil {
		return nil, err
	}
	policy.ID, policy.OrgID, policy.TargetID = id, orgID, targetID
	policy.TargetRevision, policy.Revision = targetRevision, revision
	policy.Environment = trustedsource.Environment(environment)
	policy.CreatedAt, policy.UpdatedAt = createdAt, updatedAt
	return &policy, nil
}

func (s *Store) GetEnvironmentPolicy(ctx context.Context, q db.Querier, orgID, id string) (*EnvironmentPolicy, error) {
	policy, err := scanEnvironmentPolicy(q.QueryRow(ctx, `SELECT `+environmentCols+` FROM verification_environment_policies WHERE org_id=$1 AND id=$2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return policy, err
}

func (s *Store) GetEnvironmentPolicyByTarget(ctx context.Context, q db.Querier, orgID, targetID string) (*EnvironmentPolicy, error) {
	policy, err := scanEnvironmentPolicy(q.QueryRow(ctx, `SELECT `+environmentCols+` FROM verification_environment_policies WHERE org_id=$1 AND target_id=$2`, orgID, targetID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return policy, err
}

func (s *Store) TargetEnvironment(ctx context.Context, q db.Querier, orgID, targetID string) (int64, trustedsource.Environment, error) {
	var revision int64
	var environment string
	err := q.QueryRow(ctx, `SELECT rt.revision, c.labels->>'inari.dev/environment'
		FROM resource_targets rt JOIN clusters c ON c.id=rt.resource_id
		WHERE rt.org_id=$1 AND rt.id=$2 AND rt.capability='deployment.cluster' AND rt.resource_kind='cluster'`, orgID, targetID).Scan(&revision, &environment)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", ErrNotFound
	}
	return revision, trustedsource.Environment(environment), err
}

func (s *Store) UpsertGrant(ctx context.Context, q db.Querier, grant *SuiteGrant) error {
	spec, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `INSERT INTO verification_suite_grants
		(id, org_id, environment_policy_id, suite_release_id, suite_digest, profile, grant_revision, grant_spec, expires_at, revoked_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(environment_policy_id,suite_digest,profile) DO UPDATE SET
		id=EXCLUDED.id, suite_release_id=EXCLUDED.suite_release_id, grant_revision=EXCLUDED.grant_revision,
		grant_spec=EXCLUDED.grant_spec, expires_at=EXCLUDED.expires_at, revoked_at=EXCLUDED.revoked_at, updated_at=now()
		WHERE verification_suite_grants.id=EXCLUDED.id AND
		  verification_suite_grants.grant_revision=EXCLUDED.grant_revision-1`,
		grant.ID, grant.OrgID, grant.EnvironmentPolicyID, grant.SuiteReleaseID, grant.SuiteDigest, grant.Profile,
		grant.Revision, spec, grant.ExpiresAt, grant.RevokedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

const grantCols = `id, org_id, environment_policy_id, suite_release_id, suite_digest, profile, grant_revision, grant_spec, expires_at, revoked_at`

func scanGrant(row pgx.Row) (*SuiteGrant, error) {
	var grant SuiteGrant
	var spec json.RawMessage
	var id, orgID, environmentID, releaseID, digest, profile string
	var revision int64
	var expiresAt, revokedAt *time.Time
	if err := row.Scan(&id, &orgID, &environmentID, &releaseID, &digest, &profile, &revision, &spec, &expiresAt, &revokedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(spec, &grant); err != nil {
		return nil, err
	}
	grant.ID, grant.OrgID, grant.EnvironmentPolicyID, grant.SuiteReleaseID = id, orgID, environmentID, releaseID
	grant.SuiteDigest, grant.Profile, grant.Revision = digest, profile, revision
	grant.ExpiresAt, grant.RevokedAt = expiresAt, revokedAt
	return &grant, nil
}

func (s *Store) GetGrant(ctx context.Context, q db.Querier, orgID, id string) (*SuiteGrant, error) {
	grant, err := scanGrant(q.QueryRow(ctx, `SELECT `+grantCols+` FROM verification_suite_grants WHERE org_id=$1 AND id=$2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return grant, err
}

func (s *Store) RevokeGrant(ctx context.Context, q db.Querier, orgID, id string, now time.Time) error {
	tag, err := q.Exec(ctx, `UPDATE verification_suite_grants SET revoked_at=$3, updated_at=$3 WHERE org_id=$1 AND id=$2 AND revoked_at IS NULL`, orgID, id, now)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) PutPolicy(ctx context.Context, q db.Querier, policy *VerificationPolicy, renderFingerprint string) error {
	spec, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE verification_policies SET current=false, updated_at=now() WHERE instance_id=$1 AND current`, policy.InstanceID); err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO verification_policies
		(id, org_id, instance_id, instance_uid, policy_revision, enabled, current, app_artifact_digest,
		 suite_grant_id, suite_digest, profile, policy_spec, render_fingerprint, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,true,$7,$8,$9,$10,$11,$12,$13,$14)`,
		policy.ID, policy.OrgID, policy.InstanceID, policy.InstanceUID, policy.Revision, policy.Enabled,
		policy.Binding.AppArtifactDigest, policy.Binding.SuiteGrantID, policy.Binding.SuiteDigest, policy.Binding.Profile,
		spec, renderFingerprint, policy.CreatedAt, policy.UpdatedAt)
	return err
}

func (s *Store) GetCurrentPolicy(ctx context.Context, q db.Querier, orgID, instanceID string) (*VerificationPolicy, error) {
	var policy VerificationPolicy
	var spec json.RawMessage
	var id string
	var revision int64
	var createdAt, updatedAt time.Time
	err := q.QueryRow(ctx, `SELECT policy_spec, id, policy_revision, created_at, updated_at FROM verification_policies WHERE org_id=$1 AND instance_id=$2 AND current`, orgID, instanceID).Scan(&spec, &id, &revision, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(spec, &policy); err != nil {
		return nil, fmt.Errorf("decode verification policy: %w", err)
	}
	policy.ID, policy.Revision, policy.Current = id, revision, true
	policy.CreatedAt, policy.UpdatedAt = createdAt, updatedAt
	return &policy, nil
}
