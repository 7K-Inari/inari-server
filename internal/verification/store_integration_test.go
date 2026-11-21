//go:build integration

package verification_test

import (
	"context"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	verification "github.com/7K-Inari/inari-server/internal/verification"
	"github.com/jackc/pgx/v5"
)

func TestRunStoreDedupeAndActiveCount(t *testing.T) {
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
		INSERT INTO clusters (id, org_id, name, state) VALUES ('cluster:1','org:1','kind','active');
		INSERT INTO resource_instances (id, org_id, cluster_id, catalog_item_id, version, artifact_digest, spec, commit_sha, generation)
		VALUES ('inst-1','org:1','cluster:1','hiroba/example','1.4.0','`+digestA+`','{"replicas":2}','0123456789abcdef0123456789abcdef01234567',4)`); err != nil {
		t.Fatal(err)
	}
	instance := syncedInstance()
	instance.OrgID = "org:1"
	instance.ID = "inst-1"
	if err := database.Pool.QueryRow(ctx, `SELECT uid FROM resource_instances WHERE id='inst-1'`).Scan(&instance.UID); err != nil {
		t.Fatal(err)
	}
	policy := validRunPolicy(t, instance)
	policy.OrgID = instance.OrgID
	run, err := verification.BuildRun(policy, 1, instance, policy.Trigger("manual", "req-1"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	store := verification.NewStore()
	insert := func() (bool, error) {
		var inserted bool
		err := database.WithTx(ctx, func(tx pgx.Tx) error {
			var err error
			inserted, err = store.InsertRun(ctx, tx, run)
			return err
		})
		return inserted, err
	}
	inserted, err := insert()
	if err != nil || !inserted {
		t.Fatalf("first insert = %v, %v", inserted, err)
	}
	inserted, err = insert()
	if err != nil || inserted {
		t.Fatalf("duplicate insert = %v, %v", inserted, err)
	}
	got, err := store.GetRunByKey(ctx, database.Pool, instance.OrgID, run.RunKey)
	if err != nil || got == nil || got.ID != run.ID {
		t.Fatalf("GetRunByKey = %#v, %v", got, err)
	}
	active, err := store.CountActiveRuns(ctx, database.Pool, instance.UID)
	if err != nil || active != 1 {
		t.Fatalf("active runs = %d, %v", active, err)
	}
	var attempts int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM verification_run_attempts WHERE run_id=$1`, run.ID).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("attempts = %d, %v", attempts, err)
	}
}
