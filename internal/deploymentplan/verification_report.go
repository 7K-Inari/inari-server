package deploymentplan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/7K-Inari/inari-server/internal/verification"
)

func invalidObservabilityReport(reason string) error {
	return fmt.Errorf("observability_result_invalid: %s", reason)
}

func decodeObservabilityOutcome(raw string) (*observability.VerificationResult, error) {
	if raw == "" {
		return nil, invalidObservabilityReport("typed outcome is required")
	}
	dec := json.NewDecoder(bytes.NewBufferString(raw))
	dec.DisallowUnknownFields()
	var result observability.VerificationResult
	if err := dec.Decode(&result); err != nil {
		return nil, invalidObservabilityReport("malformed outcome: " + err.Error())
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, invalidObservabilityReport("outcome must contain exactly one JSON object")
	}
	return &result, nil
}

// ApplyObservabilityReport adapts the authenticated generic verification
// stream to the observability readiness sink. The generic service performs its
// own run/policy/grant checks first; this adapter independently binds every
// subject-specific identity before changing companion readiness.
func (s *Service) ApplyObservabilityReport(ctx context.Context, orgID, clusterID string, report *agentv1.VerificationReport, run *verification.Run) error {
	if report == nil || run == nil || report.SubjectKind != "observability.companion" {
		return invalidObservabilityReport("report, run, and observability.companion subject are required")
	}
	if report.RunId != run.ID || int(report.Attempt) != run.LatestAttempt ||
		report.SuiteDigest != run.SuiteDigest || report.Profile != run.Profile ||
		report.InstanceUid != run.InstanceUID || report.AppRevision != run.AppRevision || report.AppDigest != run.AppArtifactDigest {
		return invalidObservabilityReport("report does not match the admitted run")
	}
	result, err := decodeObservabilityOutcome(report.OutcomeJson)
	if err != nil {
		return err
	}
	if report.OutcomeDigest != "" {
		digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(report.OutcomeJson)))
		if report.OutcomeDigest != digest {
			return invalidObservabilityReport("outcome digest mismatch")
		}
	}
	if result.Target.ClusterID != clusterID || result.Target.ID != report.TargetId || result.Target.Revision != report.TargetRevision {
		return invalidObservabilityReport("target or authenticated cluster mismatch")
	}
	if result.Companion.ID != report.CompanionId || result.Companion.Generation != report.CompanionGeneration ||
		result.App.PlanID != report.DeploymentPlanId || result.App.InstanceID != report.AppInstanceId ||
		result.App.SourceDigest != report.AppDigest || result.App.Revision != report.AppRevision {
		return invalidObservabilityReport("companion, plan, or application identity mismatch")
	}
	if result.Pack.Digest != report.PackDigest || result.CapabilityDigest != report.CapabilityDigest ||
		result.Suite.Digest != report.SuiteDigest || result.Suite.Profile != report.Profile {
		return invalidObservabilityReport("pack, capability, or suite identity mismatch")
	}
	if result.Run.ID != report.RunId || result.Run.Attempt != int(report.Attempt) || report.FinishedAt == nil ||
		!result.Run.FinishedAt.Equal(report.FinishedAt.AsTime()) || report.ExpiresAt == nil || !result.ExpiresAt.Equal(report.ExpiresAt.AsTime()) {
		return invalidObservabilityReport("run or evidence timestamp mismatch")
	}
	if report.Result == agentv1.VerificationResult_VERIFICATION_RESULT_PASSED && result.Result != "passed" ||
		report.Result == agentv1.VerificationResult_VERIFICATION_RESULT_FAILED && result.Result != "failed" ||
		(report.Result != agentv1.VerificationResult_VERIFICATION_RESULT_PASSED && report.Result != agentv1.VerificationResult_VERIFICATION_RESULT_FAILED) {
		return invalidObservabilityReport("terminal result mismatch")
	}
	_, err = s.ApplyVerification(ctx, orgID, result)
	return err
}
