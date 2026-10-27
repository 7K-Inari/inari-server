//go:build integration

package orchestrator

import (
	"context"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/impersonation"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

// A RACING duplicate merge delivery (two outbox replicas pass
// FindInstanceByPRURL before either marks — unlike sequential redelivery,
// which the pr_url guard acks) must not double-audit: the loser's
// MarkInstancePRMerged applies nothing, so its audit entry is skipped and
// the winner's stands.
func TestPRMergeRacingDuplicateAuditsOnce(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO clusters (id, org_id, name) VALUES ('c1','org:1','kind-dev')`); err != nil {
		t.Fatal(err)
	}
	inv := inventory.NewStore()
	inst := &types.ResourceInstance{
		ID: "inst-1", OrgID: "org:1", ClusterID: "c1", CatalogItemID: "item", Version: "v1",
		Spec: []byte(`{}`), Health: "unknown", State: types.InstanceStateDeploying,
		ManagementMode: types.ManagementModeAdopt,
		CommitSHA:      "old", PRURL: "https://github.com/acme/state/pull/3", Generation: 1,
	}
	if err := inv.Create(ctx, database.Pool, inst); err != nil {
		t.Fatal(err)
	}
	svc := &Service{db: database, instances: inv, audit: audit.NewStore()}
	// markInstancePRMerged is called with the impersonated virtual user,
	// as FinalizePRMerge does (audit requires it for system actors).
	finCtx := impersonation.WithImpersonator(ctx, impersonation.VirtualUser("org:1"))
	for i := 0; i < 2; i++ {
		if err := svc.markInstancePRMerged(finCtx, "org:1", inst.ID, inst.PRURL, "merge-sha"); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'deploy.pr_merged' AND object_id = 'inst-1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("deploy.pr_merged audit rows = %d, want 1 (racing duplicate must not double-audit)", n)
	}
}
