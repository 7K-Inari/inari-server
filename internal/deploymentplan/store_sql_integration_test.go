//go:build integration

package deploymentplan_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	"github.com/7K-Inari/inari-server/internal/deploymentplan"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
)

const integrationDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestMigrationAndSQLStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1')`); err != nil {
		t.Fatal(err)
	}
	store := deploymentplan.NewSQLStore(database)
	now := time.Now().UTC().Truncate(time.Millisecond)
	plan := &deploymentplan.Plan{
		ID: "dp-1", OrgID: "org:1", OrgSlug: "acme", Requester: "user:1", IdempotencyKey: "key-1",
		Operation: deploymentplan.OperationDeploy, Source: deploymentplan.Source{Kind: deploymentplan.SourceCatalog, ItemID: "hiroba/payments-api", Version: "1.4.0"},
		App:             deploymentplan.ArtifactPin{ItemID: "hiroba/payments-api", Version: "1.4.0", Digest: integrationDigest},
		Observability:   deploymentplan.ObservabilityInput{Mode: deploymentplan.ModeProvision, Pack: &deploymentplan.PackPin{ArtifactPin: deploymentplan.ArtifactPin{ItemID: "hiroba/observability-pack", Version: "0.2.0", Digest: integrationDigest}, RenderContract: observability.PackRenderContractV2}},
		PlanFingerprint: integrationDigest, State: "submitted", CreatedAt: now, UpdatedAt: now,
		Companion: &deploymentplan.Companion{ID: "oc-1", PlanID: "dp-1", TargetRevision: 7, TargetClusterID: "cluster-mon", TargetSelection: []byte(`{"folder":"acme/payments-api","datasource":"metrics","evaluation":"central"}`), AppSourceDigest: integrationDigest, AppRevision: "1.4.0@" + integrationDigest, Pack: deploymentplan.PackPin{ArtifactPin: deploymentplan.ArtifactPin{ItemID: "hiroba/observability-pack", Version: "0.2.0", Digest: integrationDigest}, RenderContract: observability.PackRenderContractV2}, CapabilityDigest: integrationDigest, State: "blocked_external_gate", Generation: 1, Links: []deploymentplan.Link{}, CreatedAt: now, UpdatedAt: now},
	}
	if err := store.CreatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	duplicate := plan.DeepCopy()
	duplicate.ID = "dp-duplicate"
	duplicate.Companion = nil
	if err := store.CreatePlan(ctx, duplicate); !errors.Is(err, deploymentplan.ErrIdempotencyConflict) {
		t.Fatalf("duplicate idempotency key error = %v, want ErrIdempotencyConflict", err)
	}
	got, err := store.GetPlan(ctx, "org:1", "dp-1")
	if err != nil || got.Requester != "user:1" || got.Companion.ID != "oc-1" {
		t.Fatalf("plan = %#v, %v", got, err)
	}
	byKey, err := store.GetPlanByIdempotency(ctx, "org:1", "user:1", "key-1")
	if err != nil || byKey.ID != "dp-1" {
		t.Fatalf("idempotency = %#v, %v", byKey, err)
	}
	companion, err := store.GetCompanion(ctx, "org:1", "oc-1")
	if err != nil || companion.State != "blocked_external_gate" {
		t.Fatalf("companion = %#v, %v", companion, err)
	}
	result := &observability.VerificationResult{Companion: observability.CompanionIdentity{ID: "oc-1", Generation: 1}, Target: observability.TargetIdentity{Revision: 7}, App: observability.AppIdentity{Revision: companion.AppRevision}, Pack: observability.PackIdentity{Digest: integrationDigest}, CapabilityDigest: integrationDigest, Suite: observability.SuiteIdentity{Digest: integrationDigest, Profile: "stage"}, Run: observability.RunIdentity{ID: "vr-1", Attempt: 1, FinishedAt: now}, Result: "failed", Checks: observability.VerificationChecks{}, ExpiresAt: now.Add(time.Hour)}
	companion.State = "verification_failed"
	companion.Verification = result
	companion.UpdatedAt = now.Add(time.Second)
	applied, err := store.SaveVerification(ctx, "org:1", companion, result, "")
	if err != nil || !applied {
		t.Fatalf("first verification applied=%t, err=%v", applied, err)
	}
	applied, err = store.SaveVerification(ctx, "org:1", companion, result, "")
	if err != nil || applied {
		t.Fatalf("duplicate verification applied=%t, err=%v", applied, err)
	}
	staleResult := *result
	staleResult.Run.ID = "vr-stale"
	staleResult.Run.FinishedAt = now.Add(time.Minute)
	stale := companion.DeepCopy()
	stale.Verification = &staleResult
	if applied, err := store.SaveVerification(ctx, "org:1", stale, &staleResult, ""); applied || err == nil {
		t.Fatalf("stale verification applied=%t, err=%v", applied, err)
	}
	retryResult := *result
	retryResult.Run.Attempt = 2
	retryResult.Run.FinishedAt = now.Add(2 * time.Minute)
	retryCompanion := companion.DeepCopy()
	retryCompanion.Verification = &retryResult
	expectedFirst := fmt.Sprintf("%d:%s:%d:%s", result.Companion.Generation, result.Run.ID, result.Run.Attempt, result.Suite.Digest)
	applied, err = store.SaveVerification(ctx, "org:1", retryCompanion, &retryResult, expectedFirst)
	if err != nil || !applied {
		t.Fatalf("retry verification applied=%t, err=%v", applied, err)
	}
	var receipts int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM observability_verification_results WHERE companion_id='oc-1'`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 2 {
		t.Fatalf("attempt-aware transactions left %d verification receipts, want 2", receipts)
	}
	sqlDB := stdlib.OpenDBFromPool(database.Pool)
	defer sqlDB.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("../db/migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(ctx, 44); err != nil {
		t.Fatalf("down with retry evidence: %v", err)
	}
	if _, err := provider.UpTo(ctx, 45); err != nil {
		t.Fatalf("reapply attempt migration: %v", err)
	}
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM observability_verification_results WHERE companion_id='oc-1'`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 1 {
		t.Fatalf("rollback retained %d rows for the legacy key, want 1", receipts)
	}
}

func TestBlockedCompanionCanBeSupersededByFreshPlan(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `
		INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1');
		INSERT INTO clusters (id, org_id, name, state) VALUES ('cluster-mon','org:1','Monitoring','active');
		INSERT INTO resource_targets (id, org_id, name, resource_kind, resource_id, capability) VALUES ('rt-mon','org:1','Monitoring','cluster','cluster-mon','monitoring.grafana');
		INSERT INTO resource_instances (id, org_id, cluster_id, catalog_item_id, version, spec) VALUES ('app-1','org:1','cluster-mon','hiroba/payments-api','1.4.0','{}');
	`); err != nil {
		t.Fatal(err)
	}
	store := deploymentplan.NewSQLStore(database)
	now := time.Now().UTC().Truncate(time.Millisecond)
	create := func(id string) error {
		plan := &deploymentplan.Plan{
			ID: id, OrgID: "org:1", OrgSlug: "acme", Requester: "user:1", IdempotencyKey: id,
			Operation: deploymentplan.OperationProvisionExisting, Source: deploymentplan.Source{Kind: deploymentplan.SourceCatalog, ItemID: "hiroba/payments-api", Version: "1.4.0", Digest: integrationDigest},
			App: deploymentplan.ArtifactPin{ItemID: "hiroba/payments-api", Version: "1.4.0", Digest: integrationDigest}, AppInstanceID: "app-1",
			Observability: deploymentplan.ObservabilityInput{Mode: deploymentplan.ModeProvision}, PlanFingerprint: integrationDigest, State: "submitted", CreatedAt: now, UpdatedAt: now,
			Companion: &deploymentplan.Companion{ID: "oc-" + id, PlanID: id, AppInstanceID: "app-1", TargetID: "rt-mon", TargetRevision: 7, TargetClusterID: "cluster-mon", TargetSelection: []byte(`{"folder":"acme/payments-api","datasource":"metrics","evaluation":"central"}`), AppSourceDigest: integrationDigest, AppRevision: "1.4.0@" + integrationDigest, Pack: deploymentplan.PackPin{ArtifactPin: deploymentplan.ArtifactPin{ItemID: "hiroba/observability-pack", Version: "0.2.0", Digest: integrationDigest}, RenderContract: observability.PackRenderContractV2}, CapabilityDigest: integrationDigest, State: "blocked_external_gate", Generation: 1, Links: []deploymentplan.Link{}, CreatedAt: now, UpdatedAt: now},
		}
		return store.CreatePlan(ctx, plan)
	}
	if err := create("dp-blocked-1"); err != nil {
		t.Fatal(err)
	}
	if err := create("dp-blocked-2"); err != nil {
		t.Fatalf("fresh plan could not supersede blocked intent: %v", err)
	}
}

func TestDeploymentObservabilityDownLeavesExistingTables(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDBFromPool(database.Pool)
	defer sqlDB.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("../db/migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(ctx, 42); err != nil {
		t.Fatalf("down through 0043: %v", err)
	}
	for _, table := range []string{"deployment_plans", "observability_companions", "observability_verification_results"} {
		var exists *string
		if err := database.Pool.QueryRow(ctx, `SELECT to_regclass($1)`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != nil && *exists != "" {
			t.Fatalf("table %s survived down migration", table)
		}
	}
	var targets *string
	if err := database.Pool.QueryRow(ctx, `SELECT to_regclass('resource_targets')`).Scan(&targets); err != nil {
		t.Fatal(err)
	}
	if targets == nil || *targets == "" {
		t.Fatal("down migration removed existing resource targets")
	}
}
