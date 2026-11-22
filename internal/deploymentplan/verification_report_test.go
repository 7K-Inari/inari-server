package deploymentplan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/7K-Inari/inari-server/internal/verification"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func verificationReportForResult(t *testing.T, result *observability.VerificationResult) (*agentv1.VerificationReport, *verification.Run) {
	t.Helper()
	outcome, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	runRevision := "run-revision-" + result.App.Revision
	report := &agentv1.VerificationReport{
		RunId: result.Run.ID, Attempt: uint32(result.Run.Attempt), SuiteDigest: result.Suite.Digest, Profile: result.Suite.Profile,
		SubjectKind: "observability.companion", InstanceUid: "app-uid", AppInstanceId: result.App.InstanceID,
		DeploymentPlanId: result.App.PlanID, AppRevision: runRevision, AppDigest: result.App.SourceDigest,
		TargetId: "rt-deployment", TargetRevision: 99,
		CompanionId: result.Companion.ID, CompanionGeneration: result.Companion.Generation,
		PackDigest: result.Pack.Digest, CapabilityDigest: result.CapabilityDigest,
		FinishedAt: timestamppb.New(result.Run.FinishedAt), ExpiresAt: timestamppb.New(result.ExpiresAt),
		Result:      agentv1.VerificationResult_VERIFICATION_RESULT_PASSED,
		OutcomeJson: string(outcome), OutcomeDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(outcome)),
	}
	run := &verification.Run{
		ID: result.Run.ID, LatestAttempt: result.Run.Attempt, SuiteDigest: result.Suite.Digest, Profile: result.Suite.Profile,
		InstanceID: result.App.InstanceID, InstanceUID: "app-uid", AppRevision: runRevision, AppArtifactDigest: result.App.SourceDigest,
	}
	return report, run
}

func pendingCompanionForReport(t *testing.T) (*Service, *Plan, *MemoryStore) {
	t.Helper()
	svc, _, _, _, store := serviceFixture(t)
	plan, err := submitReviewed(t, svc, deployRequest())
	if err != nil {
		t.Fatal(err)
	}
	plan.Companion.CompanionInstanceID = "companion-1"
	plan.Companion.State = "verification_pending"
	if err := store.UpdatePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	return svc, plan, store
}

func TestApplyObservabilityReportUsesAuthenticatedExistingStreamBinding(t *testing.T) {
	svc, plan, store := pendingCompanionForReport(t)
	result := resultForPlan(t, plan)
	report, run := verificationReportForResult(t, result)
	if err := svc.ApplyObservabilityReport(context.Background(), "org-1", "cluster-app", report, run, nil); err != nil {
		t.Fatalf("valid existing-stream observability report rejected: %v", err)
	}
	companion, err := store.GetCompanion(context.Background(), "org-1", plan.Companion.ID)
	if err != nil {
		t.Fatal(err)
	}
	if companion.State != "ready" || companion.Verification == nil || companion.Verification.Suite.Profile != "stage" {
		t.Fatalf("companion after report = %#v", companion)
	}
}

func TestApplyObservabilityReportRejectsMismatchedEvidence(t *testing.T) {
	for _, tc := range []struct {
		name          string
		clusterID     string
		mutateReport  func(*agentv1.VerificationReport, *verification.Run)
		mutateOutcome func(*observability.VerificationResult)
	}{
		{name: "run", mutateReport: func(r *agentv1.VerificationReport, _ *verification.Run) { r.RunId = "vr-other" }},
		{name: "attempt", mutateReport: func(r *agentv1.VerificationReport, _ *verification.Run) { r.Attempt = 2 }},
		{name: "suite", mutateReport: func(r *agentv1.VerificationReport, _ *verification.Run) {
			r.SuiteDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{name: "profile", mutateReport: func(r *agentv1.VerificationReport, _ *verification.Run) { r.Profile = "prod" }},
		{name: "app", mutateReport: func(r *agentv1.VerificationReport, _ *verification.Run) {
			r.AppDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{name: "companion generation", mutateReport: func(r *agentv1.VerificationReport, _ *verification.Run) { r.CompanionGeneration++ }},
		{name: "monitoring target", mutateOutcome: func(r *observability.VerificationResult) { r.Target.ID = "rt-other" }},
		{name: "pack", mutateReport: func(r *agentv1.VerificationReport, _ *verification.Run) {
			r.PackDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{name: "capability", mutateReport: func(r *agentv1.VerificationReport, _ *verification.Run) {
			r.CapabilityDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{name: "finished time", mutateReport: func(r *agentv1.VerificationReport, _ *verification.Run) { r.FinishedAt = nil }},
		{name: "expiry", mutateReport: func(r *agentv1.VerificationReport, _ *verification.Run) { r.ExpiresAt = nil }},
		{name: "outcome digest", mutateReport: func(r *agentv1.VerificationReport, _ *verification.Run) {
			r.OutcomeDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{name: "terminal result", mutateReport: func(r *agentv1.VerificationReport, _ *verification.Run) {
			r.Result = agentv1.VerificationResult_VERIFICATION_RESULT_FAILED
		}},
		{name: "malformed outcome", mutateOutcome: func(r *observability.VerificationResult) { r.APIVersion = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, plan, _ := pendingCompanionForReport(t)
			result := resultForPlan(t, plan)
			if tc.mutateOutcome != nil {
				tc.mutateOutcome(result)
			}
			report, run := verificationReportForResult(t, result)
			if tc.mutateReport != nil {
				tc.mutateReport(report, run)
			}
			clusterID := result.Target.ClusterID
			if tc.clusterID != "" {
				clusterID = tc.clusterID
			}
			if err := svc.ApplyObservabilityReport(context.Background(), "org-1", clusterID, report, run, nil); err == nil {
				t.Fatal("mismatched observability evidence accepted")
			}
		})
	}
}

func TestApplyObservabilityReportCanonicalizesWorkflowCompletion(t *testing.T) {
	svc, plan, store := pendingCompanionForReport(t)
	result := resultForPlan(t, plan)
	report, run := verificationReportForResult(t, result)
	workflowFinished := result.Run.FinishedAt.Add(time.Second)
	report.FinishedAt = timestamppb.New(workflowFinished)
	if err := svc.ApplyObservabilityReport(context.Background(), "org-1", "cluster-app", report, run, nil); err != nil {
		t.Fatalf("container completion before Workflow completion rejected: %v", err)
	}
	companion, err := store.GetCompanion(context.Background(), "org-1", plan.Companion.ID)
	if err != nil {
		t.Fatal(err)
	}
	if companion.Verification == nil || !companion.Verification.Run.FinishedAt.Equal(workflowFinished) {
		t.Fatalf("stored completion = %#v, want Workflow timestamp", companion.Verification)
	}
}

func TestApplyObservabilityReportRecordsTransportFailureWithoutOutcome(t *testing.T) {
	for _, tc := range []struct {
		name    string
		result  agentv1.VerificationResult
		deleted bool
		typed   bool
	}{
		{name: "failed", result: agentv1.VerificationResult_VERIFICATION_RESULT_FAILED},
		{name: "cancelled", result: agentv1.VerificationResult_VERIFICATION_RESULT_CANCELLED},
		{name: "deleted", result: agentv1.VerificationResult_VERIFICATION_RESULT_PENDING, deleted: true},
		{name: "deleted retaining pass", result: agentv1.VerificationResult_VERIFICATION_RESULT_PASSED, deleted: true},
		{name: "deleted with typed failure", result: agentv1.VerificationResult_VERIFICATION_RESULT_PASSED, deleted: true, typed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, plan, store := pendingCompanionForReport(t)
			result := resultForPlan(t, plan)
			if tc.typed {
				result.Result = "failed"
				result.Checks = observability.VerificationChecks{}
			}
			report, run := verificationReportForResult(t, result)
			report.Result = tc.result
			report.Deleted = tc.deleted
			if !tc.typed {
				report.OutcomeJson = ""
				report.OutcomeDigest = ""
			}
			if err := svc.ApplyObservabilityReport(context.Background(), "org-1", "cluster-app", report, run, nil); err != nil {
				t.Fatalf("transport-only terminal report rejected: %v", err)
			}
			companion, err := store.GetCompanion(context.Background(), "org-1", plan.Companion.ID)
			if err != nil {
				t.Fatal(err)
			}
			if companion.State != "verification_failed" || companion.Verification == nil || companion.Verification.Result != "failed" {
				t.Fatalf("companion transport failure state = %#v", companion)
			}
		})
	}
}

func TestApplyObservabilityReportRecordsTypedFailure(t *testing.T) {
	svc, plan, store := pendingCompanionForReport(t)
	result := resultForPlan(t, plan)
	result.Result = "failed"
	result.Checks = observability.VerificationChecks{}
	report, run := verificationReportForResult(t, result)
	report.Result = agentv1.VerificationResult_VERIFICATION_RESULT_FAILED
	if err := svc.ApplyObservabilityReport(context.Background(), "org-1", "cluster-app", report, run, nil); err != nil {
		t.Fatalf("typed failure rejected: %v", err)
	}
	companion, err := store.GetCompanion(context.Background(), "org-1", plan.Companion.ID)
	if err != nil {
		t.Fatal(err)
	}
	if companion.State != "verification_failed" || companion.Verification == nil || companion.Verification.Result != "failed" {
		t.Fatalf("companion failure state = %#v", companion)
	}
}
