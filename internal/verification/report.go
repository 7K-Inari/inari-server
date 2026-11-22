package verification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ObservabilityReportConsumer is the sibling's in-process sink. Raw
// observability payloads are not persisted by generic verification.
type ObservabilityReportConsumer interface {
	ApplyObservabilityReport(ctx context.Context, orgID, clusterID string, report *agentv1.VerificationReport, run *Run, tx pgx.Tx) error
}

func (s *Service) WithObservabilityConsumer(consumer ObservabilityReportConsumer) *Service {
	s.observability = consumer
	return s
}

// ApplyReport authenticates common binding using the gateway session org and
// cluster. Unknown public clients have no route to this method.
func (s *Service) ApplyReport(ctx context.Context, orgID, clusterID string, report *agentv1.VerificationReport) error {
	if s.db == nil || s.instances == nil || report == nil || report.Workflow == nil {
		return errors.New("verification_report_denied: report and Workflow identity are required")
	}
	if orgID == "" || clusterID == "" || report.RunId == "" || report.ResourceVersion == "" || report.Workflow.Kind != "Workflow" || report.Workflow.Uid == "" {
		return errors.New("verification_report_denied: authenticated org/cluster and complete Workflow identity are required")
	}
	run, err := s.store.GetRunByID(ctx, s.db.Pool, orgID, report.RunId)
	if err != nil {
		return err
	}
	instance, err := s.instances.Get(ctx, s.db.Pool, run.InstanceID)
	if err != nil {
		return err
	}
	if instance.OrgID != orgID || instance.ClusterID != clusterID || instance.UID != run.InstanceUID {
		return errors.New("verification_report_denied: authenticated cluster does not own this run")
	}
	policy, renderFingerprint, err := s.store.GetPolicyRevision(ctx, s.db.Pool, orgID, run.InstanceID, run.PolicyRevision)
	if err != nil {
		return err
	}
	grant, err := s.store.GetGrant(ctx, s.db.Pool, orgID, policy.Binding.SuiteGrantID)
	if err != nil {
		return err
	}
	environment, err := s.store.GetEnvironmentPolicy(ctx, s.db.Pool, orgID, grant.EnvironmentPolicyID)
	if err != nil {
		return err
	}
	if int(report.Attempt) != run.LatestAttempt || report.TriggerFingerprint != run.TriggerFingerprint ||
		report.SuiteDigest != run.SuiteDigest || report.Profile != run.Profile || report.RenderFingerprint != renderFingerprint ||
		report.InstanceUid != run.InstanceUID || report.AppInstanceId != run.InstanceID || report.AppRevision != run.AppRevision ||
		report.AppDigest != run.AppArtifactDigest || report.PolicyRevision != run.PolicyRevision || report.GrantRevision != run.GrantRevision ||
		report.TargetId != environment.TargetID || report.TargetRevision != environment.TargetRevision {
		return errors.New("verification_report_denied: run/app/suite/target/policy binding mismatch")
	}
	if report.SubjectKind == "" {
		report.SubjectKind = "application"
	}
	if report.SubjectKind != "application" && report.SubjectKind != "observability.companion" {
		return errors.New("verification_report_denied: unsupported subject kind")
	}
	if report.SubjectKind == "observability.companion" &&
		(policy.Binding.ParameterContract != "inari.observability.params.v1" || grant.ParameterContract != "inari.observability.params.v1") {
		return errors.New("verification_report_denied: observability subject requires its exact parameter contract")
	}
	if report.SubjectKind == "observability.companion" && !report.Deleted && report.Result == agentv1.VerificationResult_VERIFICATION_RESULT_PASSED && grant.ExpiresAt != nil &&
		(report.ExpiresAt == nil || report.ExpiresAt.AsTime().After(*grant.ExpiresAt)) {
		return errors.New("verification_report_denied: observability evidence exceeds the suite grant expiry")
	}
	if len(report.OutcomeJson) > grant.MaxResultBytes || len([]rune(report.Message)) > 1024 {
		return errors.New("verification_report_denied: outcome or message exceeds the grant limit")
	}
	observedAt, err := validReportTime(report.ObservedAt, true)
	if err != nil {
		return err
	}
	startedAt, err := validOptionalReportTime(report.StartedAt)
	if err != nil {
		return err
	}
	finishedAt, err := validOptionalReportTime(report.FinishedAt)
	if err != nil {
		return err
	}
	if startedAt != nil && finishedAt != nil && startedAt.After(*finishedAt) || finishedAt != nil && finishedAt.After(observedAt.Add(5*time.Minute)) {
		return errors.New("verification_report_denied: report timestamps are out of order")
	}
	// observedAt changes on every agent relist/reconnect. It is transport
	// metadata, not Workflow content, and must not turn an identical
	// resourceVersion replay into a receipt conflict.
	checksumReport := proto.Clone(report).(*agentv1.VerificationReport)
	checksumReport.ObservedAt = nil
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(checksumReport)
	if err != nil {
		return err
	}
	payloadSum := sha256.Sum256(payload)
	payloadDigest := "sha256:" + hex.EncodeToString(payloadSum[:])
	outcomeDigest := ""
	if report.OutcomeJson != "" {
		sum := sha256.Sum256([]byte(report.OutcomeJson))
		outcomeDigest = "sha256:" + hex.EncodeToString(sum[:])
		if report.OutcomeDigest != "" && report.OutcomeDigest != outcomeDigest {
			return errors.New("verification_report_denied: outcome digest mismatch")
		}
	}
	if run.Status == "passed" || run.Status == "failed" {
		if report.SubjectKind == "observability.companion" && !report.Deleted && report.Result == agentv1.VerificationResult_VERIFICATION_RESULT_PASSED &&
			(grant.RevokedAt != nil || grant.ExpiresAt != nil && !s.now().Before(*grant.ExpiresAt)) {
			return errors.New("verification_report_denied: passing observability evidence requires a current grant")
		}
		// Terminal replays still check receipt content. A later typed
		// observability outcome for the same terminal attempt may enrich a
		// transport-only failure, but can never change the run's terminal state.
		return s.db.WithTx(ctx, func(tx pgx.Tx) error {
			inserted, err := s.store.recordReportReceipt(ctx, tx, clusterID, run, report, payloadDigest)
			if err != nil || !inserted {
				return err
			}
			if terminalReportState(report) != run.Status {
				return ErrConflict // rolls back the newly claimed receipt
			}
			if report.SubjectKind == "observability.companion" {
				if s.observability == nil {
					return errors.New("observability sink unavailable")
				}
				return s.observability.ApplyObservabilityReport(ctx, orgID, clusterID, report, run, tx)
			}
			return nil
		})
	}
	mutation := reportMutation{
		clusterID: clusterID, status: "verification_pending", disposition: "running",
		reason: "", message: report.Message, outcomeDigest: outcomeDigest,
		startedAt: startedAt, finishedAt: finishedAt, observedAt: &observedAt,
	}
	if finishedAt != nil {
		linksExpiry := finishedAt.Add(time.Duration(policy.Retention.WorkflowTTLSeconds) * time.Second)
		mutation.linksExpireAt = &linksExpiry
	}
	var terminalEvent string
	switch {
	case report.Deleted:
		mutation.status, mutation.disposition, mutation.reason = "failed", "unavailable", "result_unavailable"
		mutation.message = "Workflow was deleted before a terminal report was retained"
		terminalEvent = "verification.failed"
	case report.Result == agentv1.VerificationResult_VERIFICATION_RESULT_PENDING:
		mutation.disposition = "running"
	case report.Result == agentv1.VerificationResult_VERIFICATION_RESULT_CANCELLED:
		mutation.status, mutation.disposition, mutation.reason = "failed", "cancelled", "workflow_cancelled"
		terminalEvent = "verification.failed"
	case report.Result == agentv1.VerificationResult_VERIFICATION_RESULT_FAILED:
		mutation.status, mutation.disposition, mutation.reason = "failed", "failed", "workflow_failed"
		terminalEvent = "verification.failed"
		if report.OutcomeJson != "" && report.SubjectKind == "application" {
			if parsed, _, err := ParseGenericOutcome([]byte(report.OutcomeJson), grant.MaxResultBytes, s.now()); err == nil && parsed.Result == "failed" {
				mutation.outcome = []byte(report.OutcomeJson)
			}
		}
	case report.Result == agentv1.VerificationResult_VERIFICATION_RESULT_PASSED:
		terminalEvent = "verification.passed"
		mutation.status, mutation.disposition = "passed", "passed"
		if finishedAt == nil {
			return errors.New("verification_report_denied: passing report has no finishedAt")
		}
		if grant.RevokedAt != nil || grant.ExpiresAt != nil && !s.now().Before(*grant.ExpiresAt) {
			mutation.status, mutation.disposition, mutation.reason = "failed", "unavailable", "grant_revoked"
			terminalEvent = "verification.failed"
			break
		}
		if report.SubjectKind == "observability.companion" {
			// The raw result stays with the deployment-plan consumer.
			break
		}
		parsed, expiresAt, err := ParseGenericOutcome([]byte(report.OutcomeJson), grant.MaxResultBytes, s.now())
		if err != nil || parsed.Result != "passed" {
			mutation.status, mutation.disposition, mutation.reason = "failed", "failed", "outcome_invalid"
			if err != nil {
				mutation.message = err.Error()
			}
			mutation.outcome = nil
			terminalEvent = "verification.failed"
			break
		}
		if report.ExpiresAt != nil && !report.ExpiresAt.AsTime().Equal(expiresAt) {
			return errors.New("verification_report_denied: report and outcome expiry mismatch")
		}
		if grant.ExpiresAt != nil && grant.ExpiresAt.Before(expiresAt) {
			expiresAt = *grant.ExpiresAt
		}
		mutation.outcome = []byte(report.OutcomeJson)
		mutation.expiresAt = &expiresAt
	default:
		return errors.New("verification_report_denied: unknown verification result")
	}
	consumeObservability := report.SubjectKind == "observability.companion" && terminalReportState(report) != "verification_pending"
	if consumeObservability && s.observability == nil {
		mutation.status, mutation.disposition, mutation.reason = "failed", "unavailable", "observability_sink_unavailable"
		terminalEvent = "verification.failed"
	}
	var applied bool
	notificationEndpointIDs := uniqueNotificationEndpoints(policy.Notifications.EndpointIDs, environment.RequiredNotificationEndpointIDs)
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		var err error
		applied, err = s.store.applyReport(ctx, tx, run, report, payloadDigest, mutation)
		if err != nil || !applied {
			return err
		}
		if consumeObservability && s.observability != nil {
			consumerReport := report
			if mutation.status == "failed" && report.Result == agentv1.VerificationResult_VERIFICATION_RESULT_PASSED {
				consumerReport = proto.Clone(report).(*agentv1.VerificationReport)
				consumerReport.Result = agentv1.VerificationResult_VERIFICATION_RESULT_FAILED
				consumerReport.OutcomeJson = ""
				consumerReport.OutcomeDigest = ""
			}
			if err := s.observability.ApplyObservabilityReport(ctx, orgID, clusterID, consumerReport, run, tx); err != nil {
				return err
			}
		}
		eventType := terminalEvent
		if eventType == "" {
			eventType = "verification.run_started"
		}
		return s.record(ctx, tx, orgID, "agent:"+clusterID, eventType, "verification_run", run.ID, map[string]any{
			"orgId": orgID, "instanceId": run.InstanceID, "instanceUid": run.InstanceUID,
			"runId": run.ID, "attempt": run.LatestAttempt, "appRevision": run.AppRevision,
			"appArtifactDigest": run.AppArtifactDigest, "suiteDigest": run.SuiteDigest, "profile": run.Profile,
			"status": mutation.status, "reasonCode": mutation.reason, "outcomeDigest": mutation.outcomeDigest,
			"notificationEndpointIds": notificationEndpointIDs,
			"automaticRollback":       false,
		})
	})
	return err
}

func validReportTime(value *timestamppb.Timestamp, required bool) (time.Time, error) {
	if value == nil {
		if required {
			return time.Time{}, errors.New("verification_report_denied: observedAt is required")
		}
		return time.Time{}, nil
	}
	if err := value.CheckValid(); err != nil {
		return time.Time{}, fmt.Errorf("verification_report_denied: invalid timestamp: %w", err)
	}
	return value.AsTime().UTC(), nil
}

// validOptionalReportTime converts an optional timestamp while preserving nil.
func validOptionalReportTime(value *timestamppb.Timestamp) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	parsed, err := validReportTime(value, false)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func uniqueNotificationEndpoints(groups ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, group := range groups {
		for _, id := range group {
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

func terminalReportState(report *agentv1.VerificationReport) string {
	if report.Deleted {
		return "failed"
	}
	switch report.Result {
	case agentv1.VerificationResult_VERIFICATION_RESULT_PASSED:
		return "passed"
	case agentv1.VerificationResult_VERIFICATION_RESULT_FAILED, agentv1.VerificationResult_VERIFICATION_RESULT_CANCELLED:
		return "failed"
	default:
		return "verification_pending"
	}
}
