package deploymentplan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/verification"
	"github.com/jackc/pgx/v5"
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

func transportFailureResult(report *agentv1.VerificationReport, companion *Companion) *observability.VerificationResult {
	finishedAt := report.ObservedAt.AsTime()
	if report.FinishedAt != nil {
		finishedAt = report.FinishedAt.AsTime()
	}
	expiresAt := finishedAt.Add(time.Nanosecond)
	if report.ExpiresAt != nil && report.ExpiresAt.AsTime().After(finishedAt) {
		expiresAt = report.ExpiresAt.AsTime()
	}
	return &observability.VerificationResult{
		APIVersion: observability.APIVersion, Kind: observability.VerificationKind,
		Companion: observability.CompanionIdentity{ID: report.CompanionId, Generation: report.CompanionGeneration},
		Target:    observability.TargetIdentity{ID: companion.TargetID, Revision: companion.TargetRevision, ClusterID: companion.TargetClusterID},
		App: observability.AppIdentity{
			PlanID: report.DeploymentPlanId, InstanceID: report.AppInstanceId, ScaffoldRunID: companion.ScaffoldRunID,
			SourceDigest: report.AppDigest, Revision: companion.AppRevision,
		},
		Pack:             observability.PackIdentity{ItemID: companion.Pack.ItemID, Version: companion.Pack.Version, Digest: companion.Pack.Digest},
		CapabilityDigest: report.CapabilityDigest,
		Suite:            observability.SuiteIdentity{Digest: report.SuiteDigest, Profile: report.Profile},
		Run:              observability.RunIdentity{ID: report.RunId, Attempt: int(report.Attempt), FinishedAt: finishedAt},
		Result:           "failed",
		ExpiresAt:        expiresAt,
	}
}

// ApplyObservabilityReport adapts the authenticated generic verification
// stream to the observability readiness sink. The generic service binds the
// run's application and execution environment; the companion separately binds
// the monitoring target. When tx is non-nil, readiness shares the report's SQL
// transaction and rolls back with receipt, Workflow, run, or audit failures.
func (s *Service) ApplyObservabilityReport(ctx context.Context, orgID, clusterID string, report *agentv1.VerificationReport, run *verification.Run, tx pgx.Tx) error {
	if report == nil || run == nil || report.SubjectKind != "observability.companion" {
		return invalidObservabilityReport("report, run, and observability.companion subject are required")
	}
	if report.RunId != run.ID || int(report.Attempt) != run.LatestAttempt ||
		report.SuiteDigest != run.SuiteDigest || report.Profile != run.Profile ||
		report.InstanceUid != run.InstanceUID || report.AppInstanceId != run.InstanceID ||
		report.AppRevision != run.AppRevision || report.AppDigest != run.AppArtifactDigest {
		return invalidObservabilityReport("report does not match the admitted run")
	}
	if report.CompanionId == "" || report.CompanionGeneration <= 0 || report.DeploymentPlanId == "" {
		return invalidObservabilityReport("companion and plan identity are required")
	}
	var result *observability.VerificationResult
	if report.OutcomeJson == "" {
		if report.Result != agentv1.VerificationResult_VERIFICATION_RESULT_FAILED &&
			report.Result != agentv1.VerificationResult_VERIFICATION_RESULT_CANCELLED && !report.Deleted {
			return invalidObservabilityReport("a terminal transport failure is required without a typed outcome")
		}
		companion, err := s.companionForVerification(ctx, db.Querier(tx), orgID, report.CompanionId)
		if err != nil {
			return err
		}
		result = transportFailureResult(report, companion)
	} else {
		var err error
		result, err = decodeObservabilityOutcome(report.OutcomeJson)
		if err != nil {
			return err
		}
	}
	if report.OutcomeDigest != "" {
		digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(report.OutcomeJson)))
		if report.OutcomeDigest != digest {
			return invalidObservabilityReport("outcome digest mismatch")
		}
	}
	if result.Companion.ID != report.CompanionId || result.Companion.Generation != report.CompanionGeneration ||
		result.App.PlanID != report.DeploymentPlanId || result.App.InstanceID != report.AppInstanceId ||
		result.App.SourceDigest != report.AppDigest {
		return invalidObservabilityReport("companion, plan, or application identity mismatch")
	}
	if result.Pack.Digest != report.PackDigest || result.CapabilityDigest != report.CapabilityDigest ||
		result.Suite.Digest != report.SuiteDigest || result.Suite.Profile != report.Profile {
		return invalidObservabilityReport("pack, capability, or suite identity mismatch")
	}
	if result.Run.ID != report.RunId || result.Run.Attempt != int(report.Attempt) {
		return invalidObservabilityReport("run identity mismatch")
	}
	if report.OutcomeJson != "" {
		if report.FinishedAt == nil || report.ExpiresAt == nil || !result.ExpiresAt.Equal(report.ExpiresAt.AsTime()) {
			return invalidObservabilityReport("evidence timestamp mismatch")
		}
		finishedAt := report.FinishedAt.AsTime()
		if result.Run.FinishedAt.After(finishedAt) || report.StartedAt != nil && result.Run.FinishedAt.Before(report.StartedAt.AsTime()) {
			return invalidObservabilityReport("container completion is outside the Workflow lifetime")
		}
		// The Workflow owns terminal time; the container cannot predict the later
		// controller timestamp when it writes its output parameter.
		result.Run.FinishedAt = finishedAt
	}
	passed := !report.Deleted && report.Result == agentv1.VerificationResult_VERIFICATION_RESULT_PASSED
	failed := report.Deleted || report.Result == agentv1.VerificationResult_VERIFICATION_RESULT_FAILED ||
		report.Result == agentv1.VerificationResult_VERIFICATION_RESULT_CANCELLED
	if !passed && !failed || passed && result.Result != "passed" || failed && result.Result != "failed" {
		return invalidObservabilityReport("terminal result mismatch")
	}
	_, err := s.applyVerification(ctx, orgID, result, db.Querier(tx))
	return err
}
