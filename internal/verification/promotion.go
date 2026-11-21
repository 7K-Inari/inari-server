package verification

import (
	"sort"
	"time"
)

// EvaluatePromotionEvidence selects the latest exact matching run. It is a
// pure predicate and has no deployment or rollback side effects.
func EvaluatePromotionEvidence(policy *PromotionPolicy, runs []Run, targetDigest string, now time.Time) PromotionDecision {
	if policy == nil || !policy.Required {
		return PromotionDecision{Allowed: true}
	}
	decision := PromotionDecision{ApprovalRequired: len(policy.ApproverTeamIDs) > 0, ApproverTeamIDs: policy.ApproverTeamIDs}
	matches := make([]Run, 0)
	for _, run := range runs {
		if policy.SourceInstanceID != "" && run.InstanceID != "" && run.InstanceID != policy.SourceInstanceID {
			continue
		}
		if run.AppArtifactDigest == targetDigest && run.SuiteDigest == policy.RequiredSuiteDigest && run.Profile == policy.RequiredProfile {
			matches = append(matches, run)
		}
	}
	if len(matches) == 0 {
		decision.ReasonCode = "verification_evidence_missing"
		return decision
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].CreatedAt.Equal(matches[j].CreatedAt) {
			return matches[i].ID > matches[j].ID
		}
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})
	latest := matches[0]
	decision.SourceRunID = latest.ID
	if latest.Status != "passed" {
		decision.ReasonCode = "verification_failed"
		return decision
	}
	if latest.ExpiresAt == nil || !now.Before(*latest.ExpiresAt) {
		decision.ReasonCode = "verification_stale"
		return decision
	}
	maxAge := 24 * time.Hour
	if policy.MaxEvidenceAge != "" {
		parsed, err := time.ParseDuration(policy.MaxEvidenceAge)
		if err != nil || parsed <= 0 {
			decision.ReasonCode = "promotion_policy_invalid"
			return decision
		}
		maxAge = parsed
	}
	if latest.UpdatedAt.Before(now.Add(-maxAge)) {
		decision.ReasonCode = "verification_stale"
		return decision
	}
	decision.Allowed = true
	return decision
}
