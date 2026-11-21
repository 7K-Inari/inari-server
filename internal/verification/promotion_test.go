package verification_test

import (
	"testing"
	"time"

	verification "github.com/7K-Inari/inari-server/internal/verification"
)

func promotionPolicy() *verification.PromotionPolicy {
	return &verification.PromotionPolicy{
		TargetInstanceID: "prod-1", SourceInstanceID: "stage-1", Required: true,
		RequiredSuiteDigest: digestC, RequiredProfile: "stage", MaxEvidenceAge: "24h",
	}
}

func promotionRun(id string, created time.Time) verification.Run {
	return verification.Run{ID: id, Status: "passed", AppArtifactDigest: digestA, SuiteDigest: digestC, Profile: "stage", CreatedAt: created, UpdatedAt: created}
}

func TestEvaluatePromotionEvidence(t *testing.T) {
	now := time.Date(2026, 11, 21, 1, 0, 0, 0, time.UTC)
	if decision := verification.EvaluatePromotionEvidence(nil, nil, digestA, now); !decision.Allowed {
		t.Fatal("absence of a promotion policy should not block existing upgrades")
	}
	run := promotionRun("vr-pass", now.Add(-time.Hour))
	run.ExpiresAt = timePtr(now.Add(time.Hour))
	if decision := verification.EvaluatePromotionEvidence(promotionPolicy(), []verification.Run{run}, digestA, now); !decision.Allowed || decision.SourceRunID != run.ID {
		t.Fatalf("valid evidence rejected: %#v", decision)
	}
	tests := []struct {
		name   string
		mutate func(*verification.Run)
		runs   func(verification.Run) []verification.Run
	}{
		{name: "wrong app digest", mutate: func(r *verification.Run) { r.AppArtifactDigest = digestB }},
		{name: "wrong suite", mutate: func(r *verification.Run) { r.SuiteDigest = digestB }},
		{name: "expired", mutate: func(r *verification.Run) { expired := now.Add(-time.Minute); r.ExpiresAt = &expired }},
		{name: "latest failed", runs: func(r verification.Run) []verification.Run {
			failed := r
			failed.ID = "vr-failed"
			failed.Status = "failed"
			failed.CreatedAt = now
			failed.UpdatedAt = now
			return []verification.Run{r, failed}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := promotionRun("vr-pass", now.Add(-time.Hour))
			r.ExpiresAt = timePtr(now.Add(time.Hour))
			if tt.mutate != nil {
				tt.mutate(&r)
			}
			runs := []verification.Run{r}
			if tt.runs != nil {
				runs = tt.runs(r)
			}
			if decision := verification.EvaluatePromotionEvidence(promotionPolicy(), runs, digestA, now); decision.Allowed {
				t.Fatalf("invalid evidence authorized promotion: %#v", decision)
			}
		})
	}
}

func timePtr(v time.Time) *time.Time { return &v }
