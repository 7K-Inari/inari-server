//go:build integration

package capabilities

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

func TestListForOrgReturnsOnlyLiveOrgCapabilities(t *testing.T) {
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
		('org:1','acme','Acme','kc-1'), ('org:2','other','Other','kc-2');
		INSERT INTO clusters (id, org_id, name) VALUES
		('cluster:1','org:1','one'), ('cluster:2','org:1','two'), ('cluster:other','org:2','other')`); err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	items := []struct {
		clusterID string
		name      string
	}{
		{"cluster:1", "monitoring/grafana"},
		{"cluster:2", "monitoring/prometheus"},
		{"cluster:other", "monitoring/other"},
	}
	for _, item := range items {
		if err := store.Upsert(ctx, database.Pool, item.clusterID, types.CapabilityItem{
			Kind: types.CapabilityKindHelmRelease, Name: item.name, Group: "helm.sh", Version: "1",
			UIHints: json.RawMessage(`{"namespace":"monitoring","status":"deployed"}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	deleted := types.CapabilityItem{Kind: types.CapabilityKindHelmRelease, Name: "monitoring/deleted", Group: "helm.sh", Version: "1"}
	if err := store.Upsert(ctx, database.Pool, "cluster:2", deleted); err != nil {
		t.Fatal(err)
	}
	if changed, err := store.SoftDelete(ctx, database.Pool, "cluster:2", deleted); err != nil || !changed {
		t.Fatalf("soft delete = %t, %v", changed, err)
	}

	capabilities, err := store.ListForOrg(ctx, database.Pool, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if len(capabilities) != 2 {
		t.Fatalf("org capabilities = %+v, want two live rows", capabilities)
	}
	byCluster := map[string]int{}
	for _, capability := range capabilities {
		byCluster[capability.ClusterID]++
		if capability.Name == "monitoring/deleted" || capability.Name == "monitoring/other" {
			t.Errorf("unexpected capability %+v", capability)
		}
	}
	if byCluster["cluster:1"] != 1 || byCluster["cluster:2"] != 1 {
		t.Errorf("capability grouping = %+v", byCluster)
	}
}
