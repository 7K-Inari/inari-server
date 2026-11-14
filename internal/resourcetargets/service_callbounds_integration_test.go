//go:build integration

package resourcetargets

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

type countingClusters struct {
	clusters  map[string]*types.Cluster
	getCalls  int
	listCalls int
}

func (f *countingClusters) GetCluster(_ context.Context, id string) (*types.Cluster, error) {
	f.getCalls++
	cluster := f.clusters[id]
	if cluster == nil {
		return nil, clusterregistry.ErrClusterNotFound
	}
	return cluster, nil
}

func (f *countingClusters) ListClusters(_ context.Context, orgID string) ([]types.Cluster, error) {
	f.listCalls++
	out := make([]types.Cluster, 0, len(f.clusters))
	for _, cluster := range f.clusters {
		if cluster.OrgID == orgID {
			out = append(out, *cluster)
		}
	}
	return out, nil
}

type countingInventory struct {
	repo                   *types.TenantGitRepo
	baselineSelectorCalls  int
	getRepoCalls           int
	listAddonsCalls        int
	baselineBatchLoadCalls int
}

func (f *countingInventory) BaselineRepoSelector(context.Context, db.Querier, string, string) (string, error) {
	f.baselineSelectorCalls++
	return f.repo.ID, nil
}

func (f *countingInventory) GetGitRepo(context.Context, db.Querier, string, string) (*types.TenantGitRepo, error) {
	f.getRepoCalls++
	return f.repo, nil
}

func (f *countingInventory) ListClusterAddons(context.Context, db.Querier, string, string) ([]*types.ClusterAddon, error) {
	f.listAddonsCalls++
	return nil, nil
}

func (f *countingInventory) ListClusterBaselineRepos(_ context.Context, _ db.Querier, _ string) (map[string]*types.TenantGitRepo, error) {
	f.baselineBatchLoadCalls++
	// The measured fixture binds every cluster to the same platform baseline.
	return map[string]*types.TenantGitRepo{"cluster:0": f.repo, "cluster:1": f.repo, "cluster:2": f.repo}, nil
}

type countingCapabilities struct {
	listCalls       int
	listForOrgCalls int
}

func (f *countingCapabilities) List(context.Context, db.Querier, string) ([]types.Capability, error) {
	f.listCalls++
	return nil, nil
}

func (f *countingCapabilities) ListForOrg(context.Context, db.Querier, string) ([]types.Capability, error) {
	f.listForOrgCalls++
	return nil, nil
}

type countingTeams struct {
	ids   []string
	calls int
}

func (f *countingTeams) ListTeams(context.Context, string) ([]types.Team, error) {
	f.calls++
	out := make([]types.Team, 0, len(f.ids))
	for _, id := range f.ids {
		out = append(out, types.Team{ID: id})
	}
	return out, nil
}

func TestServiceListAndResolveHaveBoundedBackendCalls(t *testing.T) {
	database, _, teamID, _ := setupStore(t)
	ctx := context.Background()
	az := &fakeTargetAuthz{allowed: map[string]bool{}}
	clusters := &countingClusters{clusters: map[string]*types.Cluster{}}
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("cluster:%d", i)
		clusters.clusters[id] = &types.Cluster{ID: id, OrgID: "org:store", State: types.ClusterStateActive}
	}
	inventory := &countingInventory{repo: &types.TenantGitRepo{
		ID: "repo-bounds", OrgID: "org:store", Scope: types.GitRepoScopePlatform, BaseBranch: "main", CommitPolicy: types.CommitPolicyDirect,
	}}
	capabilities := &countingCapabilities{}
	teams := &countingTeams{ids: []string{teamID}}
	store := NewStore()
	svc := NewService(database, store, DefaultRegistry(), az, nil, Sources{
		Clusters: clusters, Inventory: inventory, Capabilities: capabilities, Teams: teams,
	})
	var targetIDs []string
	for i := 0; i < 3; i++ {
		target := &Target{
			ID: fmt.Sprintf("target-bounds-%d", i), OrgID: "org:store", Name: fmt.Sprintf("target-%d", i),
			ResourceRef:  TargetResourceRef{Kind: ResourceKindCluster, ID: fmt.Sprintf("cluster:%d", i)},
			Capabilities: []string{CapabilityDeploymentCluster}, Config: json.RawMessage(`{}`), Enabled: true, Revision: 1,
		}
		if err := store.Create(ctx, database.Pool, target); err != nil {
			t.Fatal(err)
		}
		if err := store.SetGrant(ctx, database.Pool, &Grant{TargetID: target.ID, TeamID: teamID, Relation: ActionUse}); err != nil {
			t.Fatal(err)
		}
		az.allow("alice", target.ID, "viewer")
		az.allow("alice", target.ID, "use")
		targetIDs = append(targetIDs, target.ID)
	}

	listed, err := svc.List(ctx, "org:store", "alice", ListFilter{Action: ActionView, IncludeUnavailable: true})
	if err != nil || len(listed) != 3 {
		t.Fatalf("list = %d targets, err=%v", len(listed), err)
	}
	if got := az.checkCalls; got != 1 {
		t.Errorf("List Check calls = %d, want one manager check", got)
	}
	if got := az.listObjectsCalls; got != 3 {
		t.Errorf("ListObjects calls = %d, want one per action (3)", got)
	}
	if clusters.getCalls != 0 || clusters.listCalls != 1 {
		t.Errorf("cluster loads: Get=%d List=%d, want 0 per-target Gets and 1 batch List", clusters.getCalls, clusters.listCalls)
	}
	if inventory.baselineSelectorCalls != 0 || inventory.getRepoCalls != 0 || inventory.baselineBatchLoadCalls != 1 {
		t.Errorf("baseline loads: selector=%d get=%d batch=%d, want one batch load", inventory.baselineSelectorCalls, inventory.getRepoCalls, inventory.baselineBatchLoadCalls)
	}
	if inventory.listAddonsCalls != 0 || capabilities.listCalls != 0 || capabilities.listForOrgCalls != 0 || teams.calls != 0 {
		t.Errorf("deployment-only list loaded discovery/teams: addons=%d capabilities=%d capabilitiesForOrg=%d teams=%d",
			inventory.listAddonsCalls, capabilities.listCalls, capabilities.listForOrgCalls, teams.calls)
	}

	monitoring := &Target{
		ID: "target-bounds-grafana", OrgID: "org:store", Name: "grafana",
		ResourceRef:  TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:0"},
		Capabilities: []string{CapabilityMonitoringGrafana},
		Config:       json.RawMessage(strings.Replace(string(validGrafanaConfig()), "team-1", teamID, 1)), Enabled: true, Revision: 1,
	}
	if err := store.Create(ctx, database.Pool, monitoring); err != nil {
		t.Fatal(err)
	}
	if err := store.SetGrant(ctx, database.Pool, &Grant{TargetID: monitoring.ID, TeamID: teamID, Relation: ActionView}); err != nil {
		t.Fatal(err)
	}
	az.allow("alice", monitoring.ID, "viewer")
	clusters.getCalls, clusters.listCalls = 0, 0
	inventory.baselineSelectorCalls, inventory.getRepoCalls, inventory.baselineBatchLoadCalls = 0, 0, 0
	inventory.listAddonsCalls = 0
	capabilities.listCalls, capabilities.listForOrgCalls = 0, 0
	teams.calls = 0
	az.checkCalls, az.listObjectsCalls = 0, 0
	listed, err = svc.List(ctx, "org:store", "alice", ListFilter{Action: ActionView, IncludeUnavailable: true})
	if err != nil || len(listed) != 4 {
		t.Fatalf("mixed list = %d targets, err=%v", len(listed), err)
	}
	if clusters.getCalls != 0 || clusters.listCalls != 1 || inventory.baselineBatchLoadCalls != 1 {
		t.Errorf("mixed batch cluster/baseline loads = get %d, clusters %d, baselines %d", clusters.getCalls, clusters.listCalls, inventory.baselineBatchLoadCalls)
	}
	if inventory.listAddonsCalls != 1 || capabilities.listCalls != 0 || capabilities.listForOrgCalls != 1 || teams.calls != 1 {
		t.Errorf("mixed discovery loads = addons %d, capabilities %d, capabilitiesForOrg %d, teams %d; want one batch each",
			inventory.listAddonsCalls, capabilities.listCalls, capabilities.listForOrgCalls, teams.calls)
	}
	if az.checkCalls != 1 || az.listObjectsCalls != 3 {
		t.Errorf("mixed authorization calls = Check %d ListObjects %d, want 1 and 3", az.checkCalls, az.listObjectsCalls)
	}

	az.manager = true
	az.checkCalls, az.listObjectsCalls = 0, 0
	listed, err = svc.List(ctx, "org:store", "alice", ListFilter{Action: ActionView, IncludeUnavailable: true})
	if err != nil || len(listed) != 4 {
		t.Fatalf("manager list = %d targets, err=%v", len(listed), err)
	}
	if az.checkCalls != 1 || az.listObjectsCalls != 0 {
		t.Errorf("manager authorization calls = Check %d ListObjects %d, want 1 and 0", az.checkCalls, az.listObjectsCalls)
	}
	for _, target := range listed {
		if len(target.Grants) != 1 {
			t.Errorf("manager target %s grants = %d, want the batched grant", target.ID, len(target.Grants))
		}
	}

	az.manager = false
	az.checkCalls = 0
	resolved, err := svc.Resolve(ctx, ResolveInput{
		OrgID: "org:store", Subject: "alice", TargetID: targetIDs[0], Capability: CapabilityDeploymentCluster, Action: ActionUse,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := az.checkCalls; got != 2 {
		t.Errorf("Resolve Check calls = %d, want manager + requested action only", got)
	}
	if len(resolved.Target.EffectiveActions) != 2 {
		t.Errorf("resolved effective actions = %v, want view and use", resolved.Target.EffectiveActions)
	}
}
