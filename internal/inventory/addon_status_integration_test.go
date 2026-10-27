//go:build integration

package inventory

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Feature C status folding: ArgoCD health/sync for inari-addon-<id> /
// inari-addonset-<id> (and appset children inari-addon-<id>-<cluster>)
// lands on the cluster_addons row, never on a lookalike instance.
func TestApplyStatusAddonFold(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	clusterID := seedCluster(t, database, ctx, "org:1", "prod")
	s := NewStore()
	svc := NewService(database, s, audit.NewStore(), nil)

	addon := &types.ClusterAddon{
		OrgID: "org:1", ClusterID: clusterID, CatalogItem: "platform:cert-manager",
		State: types.AddonStateManaged, DeployMode: types.AddonDeployModeApplication,
		Source:       types.SourceDescriptor{Kind: types.SourceKindHelm, Helm: &types.HelmSource{RepoURL: "r", Chart: "c", Version: "v1"}},
		ArgoCDApp:    "placeholder", // replaced below once the ID is known
		ChartVersion: "v1",
	}
	if err := s.UpsertClusterAddon(ctx, database.Pool, addon); err != nil {
		t.Fatal(err)
	}
	addon.ArgoCDApp = "inari-addon-" + addon.ID
	if err := s.UpsertClusterAddon(ctx, database.Pool, addon); err != nil {
		t.Fatal(err)
	}

	// Application status folds into the addon row.
	matched, err := svc.ApplyStatus(ctx, "org:1", clusterID, StatusUpdate{
		Resource: types.ResourceRef{Kind: "Application", Name: addon.ArgoCDApp, Namespace: "argocd"},
		Health:   "healthy", Sync: "synced",
	})
	if err != nil || !matched {
		t.Fatalf("apply: matched=%v err=%v", matched, err)
	}
	got, err := s.GetClusterAddonByID(ctx, database.Pool, "org:1", addon.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Health != "healthy" || got.Sync != "synced" {
		t.Errorf("folded status = %q/%q", got.Health, got.Sync)
	}

	// Outbox carries addon.status.
	var n int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE event_type = 'addon.status'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("addon.status outbox rows = %d", n)
	}

	// A report from the WRONG cluster does not fold.
	if matched, err := svc.ApplyStatus(ctx, "org:1", "other-cluster", StatusUpdate{
		Resource: types.ResourceRef{Kind: "Application", Name: addon.ArgoCDApp, Namespace: "argocd"},
		Health:   "degraded",
	}); err != nil || matched {
		t.Errorf("cross-cluster fold: matched=%v err=%v", matched, err)
	}

	// Fleet row: an appset child Application (inari-addon-<id>-<cluster>)
	// folds into the '*' row, accepted from any of the org's clusters.
	fleet := &types.ClusterAddon{
		OrgID: "org:1", ClusterID: "*", CatalogItem: "platform:external-secrets",
		State: types.AddonStateManaged, DeployMode: types.AddonDeployModeApplicationSet,
		Source: types.SourceDescriptor{Kind: types.SourceKindHelm, Helm: &types.HelmSource{RepoURL: "r", Chart: "c", Version: "v1"}},
	}
	if err := s.UpsertClusterAddon(ctx, database.Pool, fleet); err != nil {
		t.Fatal(err)
	}
	matched, err = svc.ApplyStatus(ctx, "org:1", clusterID, StatusUpdate{
		Resource: types.ResourceRef{Kind: "Application", Name: "inari-addon-" + fleet.ID + "-prod-eu", Namespace: "argocd"},
		Health:   "progressing",
	})
	if err != nil || !matched {
		t.Fatalf("fleet child fold: matched=%v err=%v", matched, err)
	}
	gotFleet, _ := s.GetClusterAddonByID(ctx, database.Pool, "org:1", fleet.ID)
	if gotFleet.Health != "progressing" {
		t.Errorf("fleet row health = %q", gotFleet.Health)
	}

	// The ApplicationSet itself also folds.
	if matched, err := svc.ApplyStatus(ctx, "org:1", clusterID, StatusUpdate{
		Resource: types.ResourceRef{Kind: "ApplicationSet", Name: "inari-addonset-" + fleet.ID, Namespace: "argocd"},
		Health:   "healthy",
	}); err != nil || !matched {
		t.Errorf("appset fold: matched=%v err=%v", matched, err)
	}

	// A report from ANOTHER ORG's agent session does not fold, even for a
	// fleet row (the org scoping closes the cross-tenant write gap).
	if matched, err := svc.ApplyStatus(ctx, "org:2", clusterID, StatusUpdate{
		Resource: types.ResourceRef{Kind: "ApplicationSet", Name: "inari-addonset-" + fleet.ID, Namespace: "argocd"},
		Health:   "degraded",
	}); err != nil || matched {
		t.Errorf("cross-org fold: matched=%v err=%v", matched, err)
	}
	gotFleet, _ = s.GetClusterAddonByID(ctx, database.Pool, "org:1", fleet.ID)
	if gotFleet.Health != "healthy" {
		t.Errorf("fleet row health after cross-org report = %q, want healthy", gotFleet.Health)
	}

	// Plain instance names still route to the instance path (regression:
	// addon parsing must not swallow inari-<instance>).
	matched, err = svc.ApplyStatus(ctx, "org:1", clusterID, StatusUpdate{
		Resource: types.ResourceRef{Kind: "Application", Name: "inari-web-1", Namespace: "argocd"},
		Health:   "healthy",
	})
	if err != nil || matched {
		t.Errorf("unknown instance must drop: matched=%v err=%v", matched, err)
	}
}
