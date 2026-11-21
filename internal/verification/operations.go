package verification

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	contract "github.com/7K-Inari/inari-api/contract/verification/v1"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
	"github.com/jackc/pgx/v5"
)

func (s *Service) ListSuiteReleases(ctx context.Context, orgID string) ([]SuiteRelease, error) {
	return s.store.ListSuiteReleases(ctx, s.db.Pool, orgID)
}

func (s *Service) GetEnvironmentPolicy(ctx context.Context, orgID, targetID string) (*EnvironmentPolicy, error) {
	return s.store.GetEnvironmentPolicyByTarget(ctx, s.db.Pool, orgID, targetID)
}

// PreviewGrant performs the same admission and policy checks as PutGrant but
// has no identifier allocation, persistence, audit, or outbox side effects.
func (s *Service) PreviewGrant(ctx context.Context, orgID, environmentID string, grant *SuiteGrant) (*SuitePreview, error) {
	if grant == nil {
		return nil, errors.New("grant is required")
	}
	environment, err := s.store.GetEnvironmentPolicy(ctx, s.db.Pool, orgID, environmentID)
	if err != nil {
		return nil, err
	}
	release, err := s.store.GetSuiteRelease(ctx, s.db.Pool, orgID, grant.SuiteDigest)
	if err != nil {
		return nil, err
	}
	grant.OrgID, grant.EnvironmentPolicyID, grant.SuiteReleaseID = orgID, environment.ID, release.ID
	preview, err := s.PreviewSuite(ctx, SuiteAdmissionInput{
		OrgID: orgID, SourceID: release.SourceID, Descriptor: release.Descriptor,
		Environment: environment.Environment, Profile: grant.Profile,
		LegacyNonProductionException: grant.LegacyNonProductionException,
	})
	if err != nil {
		return nil, err
	}
	if err := grant.ValidateGrant(environment); err != nil {
		return nil, err
	}
	if profile := preview.Release.Suite.Profiles[grant.Profile]; profile.SideEffects != grant.SideEffect {
		return nil, errors.New("grant sideEffects must match the signed suite profile")
	}
	if err := ValidateWorkflowTemplate(preview.Release.WorkflowTemplate, &preview.Release.Suite, grant); err != nil {
		return nil, err
	}
	if err := validateRBACSubset(preview.Release.Suite.RBACRequirements, grant.AllowedRBAC); err != nil {
		return nil, err
	}
	if environment.Environment == trustedsource.EnvironmentProduction {
		maxAge, _ := time.ParseDuration(environment.MaxEvidenceAgeAtApproval)
		finished := preview.Release.EvidenceFinishedAt
		if finished.IsZero() || finished.Before(s.now().Add(-maxAge)) || finished.After(s.now().Add(5*time.Minute)) {
			return nil, errors.New("test_evidence_invalid: production grant requires fresh signed release evidence")
		}
	}
	return preview, nil
}

func (s *Service) RevokeGrant(ctx context.Context, orgID, actor, grantID string) error {
	grant, err := s.store.GetGrant(ctx, s.db.Pool, orgID, grantID)
	if err != nil {
		return err
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.RevokeGrant(ctx, tx, orgID, grantID, s.now().UTC()); err != nil {
			return err
		}
		return s.record(ctx, tx, orgID, actor, "verification.grant_revoked", "verification_grant", grantID, map[string]any{
			"orgId": orgID, "suiteDigest": grant.SuiteDigest, "profile": grant.Profile, "grantRevision": grant.Revision,
		})
	})
}

func (s *Service) DisablePolicy(ctx context.Context, orgID, subject, instanceID string) (*VerificationPolicy, error) {
	if s.db == nil || s.instances == nil || s.targets == nil {
		return nil, errors.New("verification disable dependencies are not configured")
	}
	current, err := s.store.GetCurrentPolicy(ctx, s.db.Pool, orgID, instanceID)
	if err != nil {
		return nil, err
	}
	instance, err := s.instances.Get(ctx, s.db.Pool, instanceID)
	if err != nil {
		return nil, err
	}
	if instance.OrgID != orgID || current.InstanceUID != instance.UID {
		return nil, ErrNotFound
	}
	// Disabling is a safety control, not a new execution admission. Preserve
	// the exact historical binding and re-check only the caller's current
	// target authority; registry availability and grant revocation must not
	// make a policy impossible to disable.
	resolved, err := s.targets.ResolveResource(ctx, orgID, subject, resourcetargets.CapabilityDeploymentCluster, resourcetargets.ActionUse,
		resourcetargets.TargetResourceRef{Kind: resourcetargets.ResourceKindCluster, ID: instance.ClusterID}, nil)
	if err != nil {
		return nil, err
	}
	if resolved == nil || resolved.Target.ID == "" {
		return nil, errors.New("target_stale: deployment target is unavailable")
	}
	next := *current
	next.ID, err = newVerificationID("vp")
	if err != nil {
		return nil, err
	}
	next.Revision = current.Revision + 1
	next.Enabled = false
	next.Current = true
	now := s.now().UTC()
	next.CreatedAt, next.UpdatedAt = now, now
	fingerprintInput, _ := json.Marshal(map[string]any{"policy": next, "disabled": true})
	renderFingerprint, err := contract.DigestJSON(fingerprintInput)
	if err != nil {
		return nil, err
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.PutPolicy(ctx, tx, &next, renderFingerprint); err != nil {
			return err
		}
		return s.record(ctx, tx, orgID, subject, "verification.policy_updated", "verification_policy", next.ID, map[string]any{
			"orgId": orgID, "instanceId": instanceID, "instanceUid": instance.UID,
			"policyRevision": next.Revision, "appArtifactDigest": next.Binding.AppArtifactDigest,
			"suiteDigest": next.Binding.SuiteDigest, "profile": next.Binding.Profile,
			"renderFingerprint": renderFingerprint, "externalGate": s.GateStatus().Reason, "disabled": true,
		})
	})
	if err != nil {
		return nil, err
	}
	return &next, nil
}

func (s *Service) ListRuns(ctx context.Context, orgID, instanceID string, limit int) ([]Run, error) {
	return s.store.ListRuns(ctx, s.db.Pool, orgID, instanceID, limit)
}

func (s *Service) GetRun(ctx context.Context, orgID, instanceID, runID string, subject ...string) (*Run, error) {
	run, err := s.store.GetRun(ctx, s.db.Pool, orgID, instanceID, runID)
	if err != nil {
		return nil, err
	}
	policy, _, err := s.store.GetPolicyRevision(ctx, s.db.Pool, orgID, instanceID, run.PolicyRevision)
	if err != nil {
		return run, nil
	}
	grant, err := s.store.GetGrant(ctx, s.db.Pool, orgID, policy.Binding.SuiteGrantID)
	if err != nil || grant.RevokedAt != nil || grant.ArgoUIBaseURL == "" {
		return run, nil
	}
	environment, err := s.store.GetEnvironmentPolicy(ctx, s.db.Pool, orgID, grant.EnvironmentPolicyID)
	if err != nil {
		return run, nil
	}
	if len(subject) > 0 && subject[0] != "" && s.targets != nil {
		instance, err := s.instances.Get(ctx, s.db.Pool, instanceID)
		if err != nil {
			return run, nil
		}
		resolved, err := s.targets.ResolveResource(ctx, orgID, subject[0], resourcetargets.CapabilityDeploymentCluster, resourcetargets.ActionView,
			resourcetargets.TargetResourceRef{Kind: resourcetargets.ResourceKindCluster, ID: instance.ClusterID}, nil)
		if err != nil || resolved == nil || resolved.Target.ID != environment.TargetID {
			return run, nil
		}
	}
	attempt, err := s.store.GetLatestAttempt(ctx, s.db.Pool, run.ID, run.LatestAttempt)
	if err != nil {
		return run, nil
	}
	links, err := BuildRunLinks(grant.ArgoUIBaseURL, attempt, s.now())
	if err == nil {
		run.Links = links
	}
	return run, nil
}

func (s *Service) RetryRun(ctx context.Context, orgID, subject, instanceID, runID string) (*Run, error) {
	run, err := s.store.GetRun(ctx, s.db.Pool, orgID, instanceID, runID)
	if err != nil {
		return nil, err
	}
	if run.Status != "failed" {
		return nil, errors.New("only a terminal failed run can be retried")
	}
	// Revalidate the current caller/policy before reaching the same hard gate.
	if _, err := s.GetVerification(ctx, orgID, instanceID); err != nil {
		return nil, err
	}
	return nil, ErrExternalGateClosed
}
