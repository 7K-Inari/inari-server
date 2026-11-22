//go:build integration

// These are database/agent-transport fixtures only. They do not render
// Workflow objects, write Git, or perform deployed verification.
package verification_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
	verification "github.com/7K-Inari/inari-server/internal/verification"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type reportTestFixture struct {
	database          *db.DB
	service           *verification.Service
	store             *verification.Store
	instance          *types.ResourceInstance
	policy            *verification.VerificationPolicy
	grant             *verification.SuiteGrant
	run               *verification.Run
	renderFingerprint string
}

func newReportTestFixture(t *testing.T, parameterContracts ...string) *reportTestFixture {
	t.Helper()
	parameterContract := "inari.smoke.params.v1"
	if len(parameterContracts) == 1 {
		parameterContract = parameterContracts[0]
	}
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1');
		INSERT INTO clusters (id, org_id, name, state, labels) VALUES ('cluster:1','org:1','kind','active','{"inari.dev/environment":"staging"}');
		INSERT INTO resource_targets (id, org_id, name, resource_kind, resource_id, capability) VALUES ('rt-1','org:1','kind','cluster','cluster:1','deployment.cluster');
		INSERT INTO resource_instances (id, org_id, cluster_id, catalog_item_id, version, artifact_digest, spec, commit_sha, generation, sync_state, observed_revision, sync_operation_id, sync_operation_phase)
		VALUES ('inst-1','org:1','cluster:1','hiroba/example','1.4.0','`+digestA+`','{"replicas":2}','0123456789abcdef0123456789abcdef01234567',4,'synced','0123456789abcdef0123456789abcdef01234567','op-7','Succeeded')`); err != nil {
		t.Fatal(err)
	}
	instance := syncedInstance()
	instance.OrgID = "org:1"
	instance.ClusterID = "cluster:1"
	if err := database.Pool.QueryRow(ctx, `SELECT uid FROM resource_instances WHERE id='inst-1'`).Scan(&instance.UID); err != nil {
		t.Fatal(err)
	}
	app := &catalog.AdmittedVersion{Version: &types.CatalogItemVersion{
		ItemID: instance.CatalogItemID, Version: instance.Version, ArtifactDigest: instance.ArtifactDigest,
		Payload: json.RawMessage(`{"admission":{"runtime":{"target":"web","suiteDigest":"` + digestC + `","profile":"ci","result":"passed"}}}`),
	}}
	suite := admittedSuite()
	if parameterContract != "inari.smoke.params.v1" {
		suite.Evidence.Files["suite.yaml"] = []byte(strings.Replace(string(suite.Evidence.Files["suite.yaml"]), "inari.smoke.params.v1", parameterContract, 1))
	}
	admitter := &fakeSuiteAdmitter{admitted: suite, app: app}
	service := verification.NewService(database, verification.NewStore(), admitter, inventory.NewStore(), &fakeTargetResolver{}, audit.NewStore())
	release, err := service.CreateSuiteRelease(ctx, "user:platform", verification.SuiteAdmissionInput{
		OrgID: instance.OrgID, SourceID: "hiroba", Descriptor: suite.Descriptor,
		Environment: trustedsource.EnvironmentStaging, Profile: verification.ProfileStage,
	})
	if err != nil {
		t.Fatal(err)
	}
	environmentInput := validEnvironment(trustedsource.EnvironmentStaging)
	environmentInput.OrgID = instance.OrgID
	environment, err := service.PutEnvironmentPolicy(ctx, "user:platform", environmentInput)
	if err != nil {
		t.Fatal(err)
	}
	grant := validGrant()
	grant.OrgID = instance.OrgID
	grant.EnvironmentPolicyID = environment.ID
	grant.SuiteReleaseID = release.ID
	grant.ParameterContract = parameterContract
	grant, err = service.PutGrant(ctx, "user:platform", grant)
	if err != nil {
		t.Fatal(err)
	}
	policy := validRunPolicy(t, instance)
	policy.OrgID = instance.OrgID
	policy.Binding.SuiteGrantID = grant.ID
	policy.Binding.ParameterContract = parameterContract
	if _, err := service.PutPolicy(ctx, instance.OrgID, "user:team", policy); err != nil {
		t.Fatal(err)
	}
	run, err := verification.BuildRun(policy, grant.Revision, instance, policy.Trigger("onRevisionChange", ""), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	store := verification.NewStore()
	if err := database.WithTx(ctx, func(tx pgx.Tx) error {
		inserted, err := store.InsertRun(ctx, tx, run)
		if err == nil && !inserted {
			return errors.New("run was not inserted")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var renderFingerprint string
	if err := database.Pool.QueryRow(ctx, `SELECT render_fingerprint FROM verification_policies WHERE id=$1`, policy.ID).Scan(&renderFingerprint); err != nil {
		t.Fatal(err)
	}
	return &reportTestFixture{database: database, service: service, store: store, instance: instance, policy: policy, grant: grant, run: run, renderFingerprint: renderFingerprint}
}

func (f *reportTestFixture) pendingReport() *agentv1.VerificationReport {
	now := time.Now().UTC().Truncate(time.Second)
	return &agentv1.VerificationReport{
		RunId: f.run.ID, Attempt: 1, TriggerFingerprint: f.run.TriggerFingerprint,
		SuiteDigest: f.run.SuiteDigest, Profile: f.run.Profile, RenderFingerprint: f.renderFingerprint,
		Workflow:        &agentv1.ResourceRef{Kind: "Workflow", Name: f.run.ID + "-a1", Namespace: "verification", Uid: "wf-1"},
		ResourceVersion: "42", Result: agentv1.VerificationResult_VERIFICATION_RESULT_PENDING,
		SubjectKind: "application", InstanceUid: f.run.InstanceUID, AppInstanceId: f.run.InstanceID,
		AppRevision: f.run.AppRevision, AppDigest: f.run.AppArtifactDigest, TargetId: "rt-1", TargetRevision: 1,
		PolicyRevision: f.policy.Revision, GrantRevision: f.grant.Revision,
		StartedAt: timestamppb.New(now.Add(-time.Minute)), ObservedAt: timestamppb.New(now),
	}
}

func (f *reportTestFixture) passingReport() *agentv1.VerificationReport {
	report := f.pendingReport()
	now := report.ObservedAt.AsTime()
	expires := now.Add(time.Hour)
	report.Result = agentv1.VerificationResult_VERIFICATION_RESULT_PASSED
	report.FinishedAt = timestamppb.New(now)
	report.ObservedAt = timestamppb.New(now.Add(time.Second))
	report.OutcomeJson = `{"schema":"inari.verification.outcome/v1","result":"passed","checks":[{"name":"api","state":"passed"}],"expiresAt":"` + expires.Format(time.RFC3339) + `"}`
	report.ExpiresAt = timestamppb.New(expires)
	return report
}

func TestReportReconnectReplayIgnoresObservationTime(t *testing.T) {
	ctx := context.Background()
	fixture := newReportTestFixture(t)
	report := fixture.pendingReport()
	if err := fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, report); err != nil {
		t.Fatal(err)
	}
	replay := proto.Clone(report).(*agentv1.VerificationReport)
	replay.ObservedAt = timestamppb.New(report.ObservedAt.AsTime().Add(time.Minute))
	if err := fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, replay); err != nil {
		t.Fatalf("same Workflow resourceVersion after reconnect was rejected: %v", err)
	}
	var receipts, events int
	if err := fixture.database.Pool.QueryRow(ctx, `SELECT count(*) FROM verification_report_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='verification.run_started'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if receipts != 1 || events != 1 {
		t.Fatalf("reconnect replay was not idempotent: receipts=%d events=%d", receipts, events)
	}
}

func TestReportRejectsAttemptWorkflowSubstitution(t *testing.T) {
	ctx := context.Background()
	fixture := newReportTestFixture(t)
	if err := fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, fixture.pendingReport()); err != nil {
		t.Fatal(err)
	}
	substitute := fixture.pendingReport()
	substitute.Workflow.Uid = "wf-attacker-controlled"
	substitute.Workflow.Name = fixture.run.ID + "-other"
	substitute.ResourceVersion = "43"
	if err := fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, substitute); err == nil || !strings.Contains(err.Error(), "Workflow identity") {
		t.Fatalf("different Workflow identity for the same attempt was accepted: %v", err)
	}
	attempt, err := fixture.store.GetLatestAttempt(ctx, fixture.database.Pool, fixture.run.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.WorkflowUID != "wf-1" || attempt.WorkflowName != fixture.run.ID+"-a1" {
		t.Fatalf("attempt ownership changed after rejected report: %#v", attempt)
	}
}

func TestTerminalReportStillChecksReceiptConflicts(t *testing.T) {
	ctx := context.Background()
	fixture := newReportTestFixture(t)
	report := fixture.pendingReport()
	now := report.ObservedAt.AsTime()
	expires := now.Add(time.Hour)
	report.Result = agentv1.VerificationResult_VERIFICATION_RESULT_PASSED
	report.FinishedAt = timestamppb.New(now)
	report.ObservedAt = timestamppb.New(now.Add(time.Second))
	report.OutcomeJson = `{"schema":"inari.verification.outcome/v1","result":"passed","checks":[{"name":"api","state":"passed"}],"expiresAt":"` + expires.Format(time.RFC3339) + `"}`
	report.ExpiresAt = timestamppb.New(expires)
	if err := fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, report); err != nil {
		t.Fatal(err)
	}
	conflict := proto.Clone(report).(*agentv1.VerificationReport)
	conflict.Message = "same resourceVersion, different content"
	if err := fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, conflict); !errors.Is(err, verification.ErrConflict) {
		t.Fatalf("terminal same-key content conflict error = %v, want ErrConflict", err)
	}
}

func TestGrantRevisionOneRetryCannotReplaceIdentity(t *testing.T) {
	ctx := context.Background()
	fixture := newReportTestFixture(t)
	retry := validGrant()
	retry.OrgID = fixture.instance.OrgID
	retry.EnvironmentPolicyID = fixture.grant.EnvironmentPolicyID
	retry.SuiteReleaseID = fixture.grant.SuiteReleaseID
	if _, err := fixture.service.PutGrant(ctx, "user:platform", retry); !errors.Is(err, verification.ErrConflict) {
		t.Fatalf("revision-1 retry error = %v, want ErrConflict", err)
	}
	current, err := fixture.store.GetGrant(ctx, fixture.database.Pool, fixture.instance.OrgID, fixture.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != fixture.grant.ID || current.Revision != 1 {
		t.Fatalf("grant identity/revision changed on retry: %#v", current)
	}
	update := *current
	update.Revision = 2
	update.MaxResultBytes = 32000
	updated, err := fixture.service.PutGrant(ctx, "user:platform", &update)
	if err != nil || updated.ID != current.ID || updated.Revision != 2 {
		t.Fatalf("valid grant revision update = %#v, %v", updated, err)
	}
	if _, err := fixture.service.PutGrant(ctx, "user:platform", &update); !errors.Is(err, verification.ErrConflict) {
		t.Fatalf("stale grant update error = %v, want ErrConflict", err)
	}
}

func TestGrantRevocationImmediatelyInvalidatesPromotionEvidence(t *testing.T) {
	ctx := context.Background()
	fixture := newReportTestFixture(t)
	if err := fixture.service.ApplyReport(ctx, fixture.instance.OrgID, fixture.instance.ClusterID, fixture.passingReport()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.Pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state, labels) VALUES ('cluster:prod','org:1','prod','active','{"inari.dev/environment":"production"}');
		INSERT INTO resource_instances (id, org_id, cluster_id, catalog_item_id, version, artifact_digest, spec, generation)
		VALUES ('prod-1','org:1','cluster:prod','hiroba/example','1.3.0','`+digestB+`','{}',1)`); err != nil {
		t.Fatal(err)
	}
	policy := &verification.PromotionPolicy{
		OrgID: fixture.instance.OrgID, TargetInstanceID: "prod-1", SourceInstanceID: fixture.instance.ID,
		Required: true, RequiredSuiteDigest: fixture.run.SuiteDigest, RequiredProfile: fixture.run.Profile,
		MaxEvidenceAge: "24h", Revision: 1,
	}
	if _, err := fixture.service.PutPromotionPolicy(ctx, fixture.instance.OrgID, "user:platform", policy); err != nil {
		t.Fatal(err)
	}
	before, err := fixture.service.PreviewPromotion(ctx, fixture.instance.OrgID, "prod-1", fixture.instance.Version, fixture.instance.ArtifactDigest)
	if err != nil || !before.Decision.Allowed {
		t.Fatalf("valid pre-revocation evidence rejected: %#v, %v", before, err)
	}
	if err := fixture.service.RevokeGrant(ctx, fixture.instance.OrgID, "user:platform", fixture.grant.ID); err != nil {
		t.Fatal(err)
	}
	after, err := fixture.service.PreviewPromotion(ctx, fixture.instance.OrgID, "prod-1", fixture.instance.Version, fixture.instance.ArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	if after.Decision.Allowed || after.Decision.ReasonCode != "suite_grant_denied" {
		t.Fatalf("revoked grant still authorized promotion: %#v", after.Decision)
	}
}

func TestSuiteReleaseImportIsTenantScoped(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES
		('org:1','acme','Acme','kc-1'), ('org:2','globex','Globex','kc-2')`); err != nil {
		t.Fatal(err)
	}
	service := verification.NewService(database, verification.NewStore(), &fakeSuiteAdmitter{admitted: admittedSuite()}, nil, nil, nil)
	input := verification.SuiteAdmissionInput{OrgID: "org:1", SourceID: "hiroba", Descriptor: admittedSuite().Descriptor, Environment: trustedsource.EnvironmentStaging, Profile: verification.ProfileStage}
	first, err := service.CreateSuiteRelease(ctx, "user:platform", input)
	if err != nil {
		t.Fatal(err)
	}
	input.OrgID = "org:2"
	second, err := service.CreateSuiteRelease(ctx, "user:platform", input)
	if err != nil {
		t.Fatalf("same signed suite could not be imported by a second tenant: %v", err)
	}
	if first.ID == second.ID {
		t.Fatalf("tenant-scoped releases share global primary key %q", first.ID)
	}
}

func TestDisablePolicyDoesNotRequireAnAvailableGrant(t *testing.T) {
	ctx := context.Background()
	fixture := newReportTestFixture(t)
	if err := fixture.service.RevokeGrant(ctx, fixture.instance.OrgID, "user:platform", fixture.grant.ID); err != nil {
		t.Fatal(err)
	}
	disabled, err := fixture.service.DisablePolicy(ctx, fixture.instance.OrgID, "user:team", fixture.instance.ID)
	if err != nil {
		t.Fatalf("policy could not be disabled after grant revocation: %v", err)
	}
	if disabled.Enabled || disabled.Revision != fixture.policy.Revision+1 {
		t.Fatalf("disabled policy = %#v", disabled)
	}
}
