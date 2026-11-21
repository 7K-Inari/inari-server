//go:build integration

package verification_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
	verification "github.com/7K-Inari/inari-server/internal/verification"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeTargetResolver struct {
	calls int
}

func (f *fakeTargetResolver) ResolveResource(_ context.Context, orgID, subject, capability string, action resourcetargets.Action, ref resourcetargets.TargetResourceRef, _ json.RawMessage) (*resourcetargets.ResolvedTarget, error) {
	f.calls++
	return &resourcetargets.ResolvedTarget{
		Target:  resourcetargets.Target{ID: "rt-1", OrgID: orgID, Revision: 1, ResourceRef: ref, Capabilities: []string{capability}},
		Cluster: &types.Cluster{ID: ref.ID, OrgID: orgID, Labels: map[string]string{"inari.dev/environment": "staging"}},
	}, nil
}

func TestUngatedPolicyLifecycleStopsBeforeRun(t *testing.T) {
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
		INSERT INTO resource_instances (id, org_id, cluster_id, catalog_item_id, version, artifact_digest, spec, commit_sha, generation)
		VALUES ('inst-1','org:1','cluster:1','hiroba/example','1.4.0','`+digestA+`','{"replicas":2}','0123456789abcdef0123456789abcdef01234567',4)`); err != nil {
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
	admitter := &fakeSuiteAdmitter{admitted: admittedSuite(), app: app}
	targets := &fakeTargetResolver{}
	service := verification.NewService(database, verification.NewStore(), admitter, inventory.NewStore(), targets, audit.NewStore())
	release, err := service.CreateSuiteRelease(ctx, "user:platform", verification.SuiteAdmissionInput{
		OrgID: instance.OrgID, SourceID: "hiroba", Descriptor: admittedSuite().Descriptor,
		Environment: trustedsource.EnvironmentStaging, Profile: verification.ProfileStage,
	})
	if err != nil || release == nil {
		t.Fatalf("CreateSuiteRelease = %#v, %v", release, err)
	}
	environmentInput := validEnvironment(trustedsource.EnvironmentStaging)
	environmentInput.OrgID = instance.OrgID
	environment, err := service.PutEnvironmentPolicy(ctx, "user:platform", environmentInput)
	if err != nil {
		t.Fatalf("PutEnvironmentPolicy: %v", err)
	}
	if environment.OrgID != instance.OrgID {
		t.Fatalf("environment org = %q", environment.OrgID)
	}
	grant := validGrant()
	grant.OrgID = instance.OrgID
	grant.EnvironmentPolicyID = environment.ID
	grant.SuiteReleaseID = release.ID
	grant, err = service.PutGrant(ctx, "user:platform", grant)
	if err != nil {
		t.Fatalf("PutGrant: %v", err)
	}
	policy := validRunPolicy(t, instance)
	policy.OrgID = instance.OrgID
	policy.Binding.SuiteGrantID = grant.ID
	preview, err := service.PreviewPolicy(ctx, instance.OrgID, "user:team", policy)
	if err != nil {
		t.Fatalf("PreviewPolicy: %v", err)
	}
	if preview.SideEffectsPerformed != 0 || preview.Gate.RenderAvailable || targets.calls != 1 || admitter.appCalls != 1 {
		t.Fatalf("preview side effects or revalidation mismatch: %#v targets=%d app=%d", preview, targets.calls, admitter.appCalls)
	}
	if _, err := service.PutPolicy(ctx, instance.OrgID, "user:team", policy); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	if _, err := service.PutPolicy(ctx, instance.OrgID, "user:team", policy); !errors.Is(err, verification.ErrConflict) {
		t.Fatalf("same-revision update error = %v", err)
	}
	if _, err := service.CreateManualRun(ctx, instance.OrgID, "user:team", instance.ID, "req-1"); !errors.Is(err, verification.ErrExternalGateClosed) {
		t.Fatalf("manual run error = %v", err)
	}
	var runs int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM verification_runs`).Scan(&runs); err != nil || runs != 0 {
		t.Fatalf("runs = %d, %v; closed gate must not queue work", runs, err)
	}

	// Transport-only fixture: insert a planned run directly, without a
	// renderer, and verify authenticated report binding and replay behavior.
	run, err := verification.BuildRun(policy, grant.Revision, instance, policy.Trigger("onRevisionChange", ""), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	runStore := verification.NewStore()
	if err := database.WithTx(ctx, func(tx pgx.Tx) error {
		inserted, err := runStore.InsertRun(ctx, tx, run)
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
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(time.Hour)
	outcome := `{"schema":"inari.verification.outcome/v1","result":"passed","checks":[{"name":"api","state":"passed"}],"expiresAt":"` + expires.Format(time.RFC3339) + `"}`
	report := &agentv1.VerificationReport{
		RunId: run.ID, Attempt: 1, TriggerFingerprint: run.TriggerFingerprint,
		SuiteDigest: run.SuiteDigest, Profile: run.Profile, RenderFingerprint: renderFingerprint,
		Workflow:        &agentv1.ResourceRef{Kind: "Workflow", Name: run.ID + "-a1", Namespace: "verification", Uid: "wf-1"},
		ResourceVersion: "42", Result: agentv1.VerificationResult_VERIFICATION_RESULT_PASSED,
		SubjectKind: "application", InstanceUid: run.InstanceUID, AppInstanceId: run.InstanceID,
		AppRevision: run.AppRevision, AppDigest: run.AppArtifactDigest, TargetId: "rt-1", TargetRevision: 1,
		PolicyRevision: policy.Revision, GrantRevision: grant.Revision,
		StartedAt: timestamppb.New(now.Add(-time.Minute)), FinishedAt: timestamppb.New(now), ObservedAt: timestamppb.New(now.Add(time.Second)),
		OutcomeJson: outcome, ExpiresAt: timestamppb.New(expires),
	}
	if err := service.ApplyReport(ctx, instance.OrgID, instance.ClusterID, report); err != nil {
		t.Fatalf("ApplyReport: %v", err)
	}
	gotRun, err := runStore.GetRun(ctx, database.Pool, instance.OrgID, instance.ID, run.ID)
	if err != nil || gotRun.Status != "passed" {
		t.Fatalf("run after report = %#v, %v", gotRun, err)
	}
	if err := service.ApplyReport(ctx, instance.OrgID, instance.ClusterID, report); err != nil {
		t.Fatalf("identical report replay was not idempotent: %v", err)
	}
	report.ResourceVersion = "43"
	if err := service.ApplyReport(ctx, instance.OrgID, "cluster:wrong", report); err == nil {
		t.Fatal("wrong-cluster report was accepted")
	}
}
