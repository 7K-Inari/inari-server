//go:build integration

package verification_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/7K-Inari/inari-server/internal/deploymentplan"
	verification "github.com/7K-Inari/inari-server/internal/verification"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func createObservabilityCompanion(t *testing.T, fixture *reportTestFixture) (*deploymentplan.SQLStore, *deploymentplan.Companion) {
	t.Helper()
	ctx := context.Background()
	if _, err := fixture.database.Pool.Exec(ctx, `
		INSERT INTO clusters (id, org_id, name, state) VALUES ('cluster-mon','org:1','Monitoring','active');
		INSERT INTO resource_targets (id, org_id, name, resource_kind, resource_id, capability) VALUES ('rt-mon','org:1','Monitoring','cluster','cluster-mon','monitoring.grafana');
		INSERT INTO resource_instances (id, org_id, cluster_id, catalog_item_id, version, spec) VALUES ('companion-inst','org:1','cluster-mon','hiroba/monitoring-stack','0.1.0','{}');
	`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	companion := &deploymentplan.Companion{
		ID: "oc-obs", PlanID: "dp-obs", AppInstanceID: fixture.instance.ID, CompanionInstanceID: "companion-inst",
		TargetID: "rt-mon", TargetRevision: 1, TargetClusterID: "cluster-mon", TargetSelection: []byte(`{"datasource":"mimir"}`),
		AppSourceDigest: fixture.instance.ArtifactDigest, AppRevision: fixture.instance.Version + "@" + fixture.instance.ArtifactDigest,
		Pack:             deploymentplan.PackPin{ArtifactPin: deploymentplan.ArtifactPin{ItemID: "hiroba/observability-pack", Version: "0.1.0", Digest: digestA}, RenderContract: observability.PackRenderContractV2},
		CapabilityDigest: digestB, State: "verification_pending", Generation: 1, Links: []deploymentplan.Link{}, CreatedAt: now, UpdatedAt: now,
	}
	plan := &deploymentplan.Plan{
		ID: companion.PlanID, OrgID: fixture.instance.OrgID, OrgSlug: "acme", Requester: "user:team", IdempotencyKey: "observability-report",
		Operation: deploymentplan.OperationProvisionExisting, Source: deploymentplan.Source{Kind: deploymentplan.SourceCatalog, ItemID: fixture.instance.CatalogItemID, Version: fixture.instance.Version},
		App:           deploymentplan.ArtifactPin{ItemID: fixture.instance.CatalogItemID, Version: fixture.instance.Version, Digest: fixture.instance.ArtifactDigest},
		AppInstanceID: fixture.instance.ID, AppClusterID: fixture.instance.ClusterID, CapabilityDigest: digestB,
		PlanFingerprint: digestB, State: "verification_pending", Companion: companion, CreatedAt: now, UpdatedAt: now,
	}
	store := deploymentplan.NewSQLStore(fixture.database)
	if err := store.CreatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	return store, companion
}

func observabilityPendingReport(fixture *reportTestFixture, companion *deploymentplan.Companion) *agentv1.VerificationReport {
	report := fixture.pendingReport()
	report.SubjectKind = "observability.companion"
	report.CompanionId = companion.ID
	report.CompanionGeneration = companion.Generation
	report.DeploymentPlanId = companion.PlanID
	report.PackDigest = companion.Pack.Digest
	report.CapabilityDigest = companion.CapabilityDigest
	return report
}

func failedObservabilityResult(report *agentv1.VerificationReport, companion *deploymentplan.Companion) *observability.VerificationResult {
	finishedAt := report.FinishedAt.AsTime()
	return &observability.VerificationResult{
		APIVersion: observability.APIVersion, Kind: observability.VerificationKind,
		Companion:        observability.CompanionIdentity{ID: report.CompanionId, Generation: report.CompanionGeneration},
		Target:           observability.TargetIdentity{ID: companion.TargetID, Revision: companion.TargetRevision, ClusterID: companion.TargetClusterID},
		App:              observability.AppIdentity{PlanID: report.DeploymentPlanId, InstanceID: report.AppInstanceId, SourceDigest: report.AppDigest, Revision: companion.AppRevision},
		Pack:             observability.PackIdentity{ItemID: companion.Pack.ItemID, Version: companion.Pack.Version, Digest: companion.Pack.Digest},
		CapabilityDigest: report.CapabilityDigest, Suite: observability.SuiteIdentity{Digest: report.SuiteDigest, Profile: report.Profile},
		Run:    observability.RunIdentity{ID: report.RunId, Attempt: int(report.Attempt), FinishedAt: finishedAt.Add(-time.Second)},
		Result: "failed", ExpiresAt: finishedAt.Add(time.Hour),
	}
}

func TestObservabilityReportAndCompanionAreAtomic(t *testing.T) {
	for _, tc := range []struct {
		name              string
		mutate            func(*agentv1.VerificationReport)
		repair            func(*agentv1.VerificationReport)
		expectedError     error
		expectedErrorText string
	}{
		{
			name: "receipt conflict", mutate: func(report *agentv1.VerificationReport) {},
			repair: func(report *agentv1.VerificationReport) { report.ResourceVersion = "43" }, expectedError: verification.ErrConflict,
		},
		{
			name: "Workflow identity mismatch", mutate: func(report *agentv1.VerificationReport) {
				report.Workflow.Uid = "wf-other"
				report.ResourceVersion = "43"
			},
			repair: func(report *agentv1.VerificationReport) { report.Workflow.Uid = "wf-1" }, expectedErrorText: "Workflow identity",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fixture := newReportTestFixture(t, "inari.observability.params.v1")
			store, companion := createObservabilityCompanion(t, fixture)
			consumer := deploymentplan.NewService(fixture.database, store)
			fixture.service.WithObservabilityConsumer(consumer)
			pending := observabilityPendingReport(fixture, companion)
			if err := fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, pending); err != nil {
				t.Fatal(err)
			}
			terminal := observabilityPendingReport(fixture, companion)
			terminal.Result = agentv1.VerificationResult_VERIFICATION_RESULT_FAILED
			terminal.FinishedAt = timestamppb.New(pending.ObservedAt.AsTime())
			terminal.ExpiresAt = timestamppb.New(pending.ObservedAt.AsTime().Add(time.Hour))
			outcome, err := json.Marshal(failedObservabilityResult(terminal, companion))
			if err != nil {
				t.Fatal(err)
			}
			terminal.OutcomeJson = string(outcome)
			tc.mutate(terminal)
			err = fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, terminal)
			if tc.expectedError != nil && !errors.Is(err, tc.expectedError) {
				t.Fatalf("terminal report error = %v, want %v", err, tc.expectedError)
			}
			if tc.expectedErrorText != "" && (err == nil || !strings.Contains(err.Error(), tc.expectedErrorText)) {
				t.Fatalf("terminal report error = %v, want %q", err, tc.expectedErrorText)
			}
			unchanged, err := store.GetCompanion(ctx, fixture.instance.OrgID, companion.ID)
			if err != nil {
				t.Fatal(err)
			}
			if unchanged.State != "verification_pending" || unchanged.Verification != nil {
				t.Fatalf("rejected report changed companion: %#v", unchanged)
			}
			tc.repair(terminal)
			if err := fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, terminal); err != nil {
				t.Fatalf("corrected terminal report: %v", err)
			}
			applied, err := store.GetCompanion(ctx, fixture.instance.OrgID, companion.ID)
			if err != nil {
				t.Fatal(err)
			}
			if applied.State != "verification_failed" || applied.Verification == nil || !applied.Verification.Run.FinishedAt.Equal(terminal.FinishedAt.AsTime()) {
				t.Fatalf("applied companion = %#v", applied)
			}
			if applied.AppInstanceID != fixture.instance.ID || applied.TargetID != "rt-mon" || applied.TargetClusterID != "cluster-mon" {
				t.Fatalf("application/monitoring target binding changed: %#v", applied)
			}
		})
	}
}

func TestTerminalObservabilityReplayRequiresCurrentGrant(t *testing.T) {
	ctx := context.Background()
	fixture := newReportTestFixture(t, "inari.observability.params.v1")
	store, companion := createObservabilityCompanion(t, fixture)
	fixture.service.WithObservabilityConsumer(deploymentplan.NewService(fixture.database, store))
	if err := fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, fixture.passingReport()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.Pool.Exec(ctx, `UPDATE verification_suite_grants SET revoked_at=now() WHERE id=$1`, fixture.grant.ID); err != nil {
		t.Fatal(err)
	}
	late := fixture.passingReport()
	late.ResourceVersion = "43"
	late.SubjectKind = "observability.companion"
	late.CompanionId = companion.ID
	late.CompanionGeneration = companion.Generation
	late.DeploymentPlanId = companion.PlanID
	late.PackDigest = companion.Pack.Digest
	late.CapabilityDigest = companion.CapabilityDigest
	if err := fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, late); err == nil || !strings.Contains(err.Error(), "current grant") {
		t.Fatalf("revoked terminal replay error = %v", err)
	}
	unchanged, err := store.GetCompanion(ctx, fixture.instance.OrgID, companion.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.State != "verification_pending" || unchanged.Verification != nil {
		t.Fatalf("revoked grant initialized companion readiness: %#v", unchanged)
	}
}

func TestObservabilityEvidenceCannotOutliveGrant(t *testing.T) {
	ctx := context.Background()
	fixture := newReportTestFixture(t, "inari.observability.params.v1")
	consumer := &capturingObservabilityConsumer{}
	fixture.service.WithObservabilityConsumer(consumer)
	report := fixture.passingReport()
	report.SubjectKind = "observability.companion"
	report.CompanionId = "oc-obs"
	report.CompanionGeneration = 1
	report.DeploymentPlanId = "dp-obs"
	grantExpiry := report.FinishedAt.AsTime().Add(time.Minute)
	if _, err := fixture.database.Pool.Exec(ctx, `UPDATE verification_suite_grants SET expires_at=$2 WHERE id=$1`, fixture.grant.ID, grantExpiry); err != nil {
		t.Fatal(err)
	}
	err := fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, report)
	if err == nil || !strings.Contains(err.Error(), "grant expiry") {
		t.Fatalf("report beyond grant expiry error = %v", err)
	}
	if consumer.calls != 0 {
		t.Fatalf("expired-grant evidence reached consumer %d times", consumer.calls)
	}
}
