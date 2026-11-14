//go:build integration

package resourcetargets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

type fakeClusters struct{ cluster *types.Cluster }

func (f fakeClusters) GetCluster(context.Context, string) (*types.Cluster, error) {
	return f.cluster, nil
}

func (f fakeClusters) ListClusters(_ context.Context, orgID string) ([]types.Cluster, error) {
	if f.cluster == nil || f.cluster.OrgID != orgID {
		return nil, nil
	}
	return []types.Cluster{*f.cluster}, nil
}

type fakeInventory struct {
	repo      *types.TenantGitRepo
	addons    []*types.ClusterAddon
	clusterID string
}

func (f fakeInventory) BaselineRepoSelector(context.Context, db.Querier, string, string) (string, error) {
	if f.repo == nil {
		return "", nil
	}
	return f.repo.ID, nil
}
func (f fakeInventory) GetGitRepo(context.Context, db.Querier, string, string) (*types.TenantGitRepo, error) {
	return f.repo, nil
}
func (f fakeInventory) ListClusterBaselineRepos(_ context.Context, _ db.Querier, orgID string) (map[string]*types.TenantGitRepo, error) {
	out := map[string]*types.TenantGitRepo{}
	if f.repo != nil && f.repo.OrgID == orgID && f.clusterID != "" {
		out[f.clusterID] = f.repo
	}
	return out, nil
}
func (f fakeInventory) ListClusterAddons(context.Context, db.Querier, string, string) ([]*types.ClusterAddon, error) {
	return f.addons, nil
}

type fakeCapabilities struct{ capabilities []types.Capability }

func (f fakeCapabilities) List(context.Context, db.Querier, string) ([]types.Capability, error) {
	return f.capabilities, nil
}

func (f fakeCapabilities) ListForOrg(context.Context, db.Querier, string) ([]types.Capability, error) {
	return f.capabilities, nil
}

type fakeTeams struct{ ids []string }

func (f fakeTeams) ListTeams(context.Context, string) ([]types.Team, error) {
	out := make([]types.Team, 0, len(f.ids))
	for _, id := range f.ids {
		out = append(out, types.Team{ID: id})
	}
	return out, nil
}

type fakeTargetAuthz struct {
	manager          bool
	managerSubjects  map[string]bool
	allowed          map[string]bool
	err              error
	checkCalls       int
	listObjectsCalls int
}

func (f *fakeTargetAuthz) key(subject, relation, object string) string {
	return subject + "|" + relation + "|" + object
}
func (f *fakeTargetAuthz) Check(_ context.Context, subject, relation, object string) (bool, error) {
	f.checkCalls++
	if f.err != nil {
		return false, f.err
	}
	if relation == authz.RelationResourceTargetsManage && object == authz.OrgObject("org:store") {
		return f.manager || f.managerSubjects[subject], nil
	}
	return f.allowed[f.key(subject, relation, object)], nil
}
func (f *fakeTargetAuthz) ListObjects(_ context.Context, subject, relation, objectType string) ([]string, error) {
	f.listObjectsCalls++
	if f.err != nil {
		return nil, f.err
	}
	var out []string
	for key, allowed := range f.allowed {
		if !allowed {
			continue
		}
		parts := strings.Split(key, "|")
		if len(parts) == 3 && parts[0] == subject && parts[1] == relation && strings.HasPrefix(parts[2], objectType+":") {
			out = append(out, parts[2])
		}
	}
	return out, nil
}
func (f *fakeTargetAuthz) allow(subject, targetID, relation string) {
	f.allowed[f.key(authz.UserObject(subject), relation, authz.ResourceTargetObject(targetID))] = true
}

func serviceFixture(t *testing.T) (*Service, *db.DB, *fakeTargetAuthz, string, ResourceSnapshot) {
	t.Helper()
	database, _, teamID, _ := setupStore(t)
	snapshot := validGrafanaSnapshot()
	snapshot.Cluster.ID = "cluster:store"
	snapshot.Cluster.OrgID = "org:store"
	snapshot.BaselineRepo.ID = "repo-store"
	snapshot.BaselineRepo.OrgID = "org:store"
	snapshot.Addons[0].OrgID = "org:store"
	snapshot.Addons[0].ClusterID = "cluster:store"
	snapshot.Capabilities[0].ClusterID = "cluster:store"
	snapshot.TeamIDs = []string{teamID}
	az := &fakeTargetAuthz{allowed: map[string]bool{}}
	svc := NewService(database, NewStore(), DefaultRegistry(), az, audit.NewStore(), Sources{
		Clusters:     fakeClusters{cluster: snapshot.Cluster},
		Inventory:    fakeInventory{repo: snapshot.BaselineRepo, addons: snapshot.Addons, clusterID: snapshot.Cluster.ID},
		Capabilities: fakeCapabilities{capabilities: snapshot.Capabilities},
		Teams:        fakeTeams{ids: []string{teamID}},
	})
	return svc, database, az, teamID, snapshot
}

func TestServiceDeploymentListResolveAndImmediateRevocation(t *testing.T) {
	svc, _, az, teamID, _ := serviceFixture(t)
	ctx := context.Background()
	target, err := svc.Create(ctx, "org:store", "user:admin", CreateInput{
		Name: "deployment", ResourceRef: TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capability: CapabilityDeploymentCluster, Config: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("create deployment target: %v", err)
	}
	if _, err := svc.SetGrant(ctx, target.OrgID, target.ID, teamID, ActionUse, "user:admin"); err != nil {
		t.Fatal(err)
	}
	az.allow("alice", target.ID, authz.RelationViewer)
	az.allow("alice", target.ID, authz.RelationUse)

	listed, err := svc.List(ctx, target.OrgID, "alice", ListFilter{Capability: CapabilityDeploymentCluster, Action: ActionUse})
	if err != nil || len(listed) != 1 {
		t.Fatalf("use list = %+v, %v", listed, err)
	}
	if len(listed[0].EffectiveActions) != 2 {
		t.Errorf("effective actions = %v, want view and use", listed[0].EffectiveActions)
	}
	resolved, err := svc.Resolve(ctx, ResolveInput{OrgID: target.OrgID, Subject: "alice", TargetID: target.ID,
		Capability: CapabilityDeploymentCluster, Action: ActionUse, ExpectedRevision: 1})
	if err != nil || resolved.Cluster.ID != "cluster:store" || resolved.Target.Binding.BaselineRepoID == "" {
		t.Fatalf("resolve = %+v, %v", resolved, err)
	}
	if _, err := svc.Resolve(ctx, ResolveInput{OrgID: target.OrgID, Subject: "alice", TargetID: target.ID,
		Capability: CapabilityDeploymentCluster, Action: ActionUse, ExpectedRevision: 99}); !errors.Is(err, ErrStaleRevision) {
		t.Errorf("stale resolve = %v, want ErrStaleRevision", err)
	}

	az.allowed = map[string]bool{}
	listed, err = svc.List(ctx, target.OrgID, "alice", ListFilter{Action: ActionUse})
	if err != nil || len(listed) != 0 {
		t.Errorf("unentitled list = %+v, %v", listed, err)
	}
	if _, err := svc.Resolve(ctx, ResolveInput{OrgID: target.OrgID, Subject: "alice", TargetID: target.ID, Action: ActionUse}); !errors.Is(err, ErrTargetDenied) {
		t.Errorf("direct submit after list denial = %v, want denied", err)
	}

	// Restore a stale cached FGA allow, then remove only the current DB grant.
	// The narrowing fence must still deny immediately.
	az.allow("alice", target.ID, authz.RelationUse)
	if err := svc.RevokeGrant(ctx, target.OrgID, target.ID, teamID, "user:admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Resolve(ctx, ResolveInput{OrgID: target.OrgID, Subject: "alice", TargetID: target.ID, Action: ActionUse}); !errors.Is(err, ErrTargetDenied) {
		t.Errorf("revoked submit = %v, want denied", err)
	}
}

func TestServiceMonitoringAndDeploymentShareResolver(t *testing.T) {
	svc, database, az, teamID, _ := serviceFixture(t)
	ctx := context.Background()
	target, err := svc.Create(ctx, "org:store", "user:admin", CreateInput{
		Name: "central Grafana", ResourceRef: TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capability: CapabilityMonitoringGrafana,
		Config:     json.RawMessage(strings.Replace(string(validGrafanaConfig()), "team-1", teamID, 1)),
	})
	if err != nil {
		t.Fatalf("create Grafana target: %v", err)
	}
	if _, err := svc.SetGrant(ctx, target.OrgID, target.ID, teamID, ActionProvision, "user:admin"); err != nil {
		t.Fatal(err)
	}
	az.allow("alice", target.ID, authz.RelationViewer)
	az.allow("alice", target.ID, authz.RelationProvision)
	listed, err := svc.List(ctx, target.OrgID, "alice", ListFilter{Capability: CapabilityMonitoringGrafana, Action: ActionProvision})
	if err != nil || len(listed) != 1 {
		t.Fatalf("provision list = %+v, %v", listed, err)
	}
	resolved, err := svc.Resolve(ctx, ResolveInput{OrgID: target.OrgID, Subject: "alice", TargetID: target.ID,
		Capability: CapabilityMonitoringGrafana, Action: ActionProvision,
		Selection: json.RawMessage(`{"folder":"acme/apps","datasource":"metrics","evaluation":"central"}`)})
	if err != nil || !resolved.Approval.Required {
		t.Fatalf("Grafana resolve = %+v, %v", resolved, err)
	}
	if _, err := svc.Resolve(ctx, ResolveInput{OrgID: target.OrgID, Subject: "alice", TargetID: target.ID,
		Action: ActionProvision, Selection: json.RawMessage(`{"folder":"other","datasource":"metrics","evaluation":"central"}`)}); err == nil {
		t.Fatal("folder policy bypass must fail")
	}

	// A stale provision check cannot survive a downgrade to view.
	if _, err := svc.SetGrant(ctx, target.OrgID, target.ID, teamID, ActionView, "user:admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Resolve(ctx, ResolveInput{OrgID: target.OrgID, Subject: "alice", TargetID: target.ID, Action: ActionProvision}); !errors.Is(err, ErrTargetDenied) {
		t.Errorf("downgraded provision = %v, want denied", err)
	}
	var payload string
	if err := database.Pool.QueryRow(ctx, `SELECT COALESCE(payload::text, '') FROM audit_events
		WHERE action='resource_target.created' AND object_id=$1`, target.ID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, "grafana.example") || strings.Contains(payload, "addon-1") {
		t.Errorf("audit leaked raw target config: %s", payload)
	}
}

func TestDisableTargetDoesNotRequireStaleEvidence(t *testing.T) {
	svc, _, _, teamID, snapshot := serviceFixture(t)
	ctx := context.Background()
	target, err := svc.Create(ctx, "org:store", "user:admin", CreateInput{
		Name: "Grafana", ResourceRef: TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capability: CapabilityMonitoringGrafana,
		Config:     json.RawMessage(strings.Replace(string(validGrafanaConfig()), "team-1", teamID, 1)),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Cluster.State = types.ClusterStateRevoked
	enabled := false
	updated, err := svc.Update(ctx, target.OrgID, target.ID, "user:admin", PatchInput{Enabled: &enabled, Revision: 1})
	if err != nil {
		t.Fatalf("disable with stale evidence: %v", err)
	}
	if updated.Enabled {
		t.Fatal("target remained enabled")
	}
}

func TestServiceManagerAndAuthorizationFailure(t *testing.T) {
	svc, _, az, _, _ := serviceFixture(t)
	ctx := context.Background()
	target, err := svc.Create(ctx, "org:store", "user:admin", CreateInput{
		Name: "deployment", ResourceRef: TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capability: CapabilityDeploymentCluster,
	})
	if err != nil {
		t.Fatal(err)
	}
	az.manager = true
	if _, err := svc.Resolve(ctx, ResolveInput{OrgID: target.OrgID, Subject: "admin", TargetID: target.ID, Action: ActionUse}); err != nil {
		t.Errorf("manager resolve: %v", err)
	}
	az.err = fmt.Errorf("OpenFGA unavailable")
	if _, err := svc.List(ctx, target.OrgID, "alice", ListFilter{}); err == nil {
		t.Fatal("authorization backend failure must fail list closed")
	}
}
