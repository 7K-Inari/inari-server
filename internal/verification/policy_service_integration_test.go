//go:build integration

package verification_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
	verification "github.com/7K-Inari/inari-server/internal/verification"
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
}
