package verification

import (
	"context"
	"errors"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/jackc/pgx/v5"
)

// PromotionPreview is an explicit user-reviewed decision, never an automatic
// channel or instance mutation.
type PromotionPreview struct {
	Policy        *PromotionPolicy  `json:"policy,omitempty"`
	Decision      PromotionDecision `json:"decision"`
	TargetVersion string            `json:"targetVersion"`
	TargetDigest  string            `json:"targetDigest"`
}

func (s *Service) PutPromotionPolicy(ctx context.Context, orgID, actor string, policy *PromotionPolicy) (*PromotionPolicy, error) {
	if policy == nil {
		return nil, errors.New("promotion policy is required")
	}
	policy.OrgID = orgID
	if policy.MaxEvidenceAge == "" {
		policy.MaxEvidenceAge = "24h"
	}
	if err := validatePromotionPolicy(policy); err != nil {
		return nil, err
	}
	environment, err := s.store.InstanceEnvironment(ctx, s.db.Pool, orgID, policy.TargetInstanceID)
	if err != nil {
		return nil, err
	}
	if environment == "" {
		environment = string(trustedsource.EnvironmentProduction)
	}
	if environment != string(trustedsource.EnvironmentProduction) {
		return nil, errors.New("promotion target must be a production instance")
	}
	sourceEnvironment, err := s.store.InstanceEnvironment(ctx, s.db.Pool, orgID, policy.SourceInstanceID)
	if err != nil {
		return nil, err
	}
	if sourceEnvironment == string(trustedsource.EnvironmentProduction) {
		return nil, errors.New("promotion source must be a non-production instance")
	}
	current, err := s.store.GetPromotionPolicy(ctx, s.db.Pool, orgID, policy.TargetInstanceID)
	now := s.now().UTC()
	if errors.Is(err, ErrNotFound) {
		if policy.Revision != 1 {
			return nil, ErrConflict
		}
	} else if err != nil {
		return nil, err
	} else if policy.Revision != current.Revision+1 {
		return nil, ErrConflict
	}
	policy.ID, err = newVerificationID("vpp")
	if err != nil {
		return nil, err
	}
	policy.Current, policy.CreatedAt, policy.UpdatedAt = true, now, now
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.PutPromotionPolicy(ctx, tx, policy); err != nil {
			return err
		}
		return s.record(ctx, tx, orgID, actor, "verification.promotion_policy_updated", "verification_promotion_policy", policy.ID, map[string]any{
			"orgId": orgID, "targetInstanceId": policy.TargetInstanceID, "sourceInstanceId": policy.SourceInstanceID,
			"suiteDigest": policy.RequiredSuiteDigest, "profile": policy.RequiredProfile, "policyRevision": policy.Revision,
		})
	})
	return policy, err
}

func (s *Service) GetPromotionPolicy(ctx context.Context, orgID, targetInstanceID string) (*PromotionPolicy, error) {
	return s.store.GetPromotionPolicy(ctx, s.db.Pool, orgID, targetInstanceID)
}

func (s *Service) PreviewPromotion(ctx context.Context, orgID, targetInstanceID, toVersion, toDigest string) (*PromotionPreview, error) {
	policy, err := s.store.GetPromotionPolicy(ctx, s.db.Pool, orgID, targetInstanceID)
	if errors.Is(err, ErrNotFound) {
		return &PromotionPreview{Decision: PromotionDecision{Allowed: true}, TargetVersion: toVersion, TargetDigest: toDigest}, nil
	}
	if err != nil {
		return nil, err
	}
	target, err := s.instances.Get(ctx, s.db.Pool, targetInstanceID)
	if err != nil {
		return nil, err
	}
	source, err := s.instances.Get(ctx, s.db.Pool, policy.SourceInstanceID)
	if err != nil {
		return nil, err
	}
	if target.OrgID != orgID || source.OrgID != orgID || target.CatalogItemID != source.CatalogItemID || source.Version != toVersion {
		return &PromotionPreview{Policy: policy, Decision: PromotionDecision{Allowed: false, ReasonCode: "app_version_incompatible"}, TargetVersion: toVersion, TargetDigest: toDigest}, nil
	}
	runs, err := s.store.ListRuns(ctx, s.db.Pool, orgID, source.ID, 200)
	if err != nil {
		return nil, err
	}
	decision := EvaluatePromotionEvidence(policy, runs, toDigest, s.now())
	return &PromotionPreview{Policy: policy, Decision: decision, TargetVersion: toVersion, TargetDigest: toDigest}, nil
}

// CheckPromotion is called by orchestrator for every non-rollback version
// upgrade, including approval resume. Absence of a policy preserves upgrades.
func (s *Service) CheckPromotion(ctx context.Context, orgID, instanceID, toVersion, toDigest, requester string) error {
	preview, err := s.PreviewPromotion(ctx, orgID, instanceID, toVersion, toDigest)
	if err != nil {
		return err
	}
	if !preview.Decision.Allowed {
		return errors.New("promotion_gate_failed: " + preview.Decision.ReasonCode)
	}
	// Approvals remain the orchestrator's independent explicit gate. This
	// method never promotes, rolls back, or moves a channel by itself.
	return nil
}

func (s *Service) WithPromoter(promoter Promoter) *Service {
	s.promoter = promoter
	return s
}

// Promote performs an explicit reviewed upgrade. Verification success never
// invokes this method automatically, and failure never invokes Rollback.
func (s *Service) Promote(ctx context.Context, orgID, instanceID, toVersion, toDigest, repoID, requester string) (*orchestrator.DeployResult, error) {
	if s.promoter == nil {
		return nil, errors.New("promotion executor is not configured")
	}
	preview, err := s.PreviewPromotion(ctx, orgID, instanceID, toVersion, toDigest)
	if err != nil {
		return nil, err
	}
	if !preview.Decision.Allowed {
		return nil, errors.New("promotion_gate_failed: " + preview.Decision.ReasonCode)
	}
	return s.promoter.Upgrade(ctx, orgID, instanceID, toVersion, repoID, requester)
}
