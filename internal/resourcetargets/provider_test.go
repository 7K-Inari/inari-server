package resourcetargets

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestDeploymentClusterProvider(t *testing.T) {
	p := deploymentClusterProvider{}
	if _, err := p.NormalizeConfig(json.RawMessage(`{"secret":"no"}`)); err == nil {
		t.Fatal("non-empty deployment config must be rejected")
	}
	now := time.Now()
	snapshot := ResourceSnapshot{
		Cluster:      &types.Cluster{ID: "cluster:1", OrgID: "org:1", State: types.ClusterStateActive, LastSeenAt: &now},
		BaselineRepo: &types.TenantGitRepo{ID: "repo-1", OrgID: "org:1", Scope: types.GitRepoScopePlatform, BaseBranch: "main", CommitPolicy: types.CommitPolicyPullRequest},
	}
	target := &Target{ResourceRef: ResourceRef{Kind: ResourceKindCluster, ID: "cluster:1"}, Config: json.RawMessage(`{}`)}
	binding, readiness, err := p.Resolve(target, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if readiness.State != ReadinessReady || !readiness.State.Selectable() {
		t.Errorf("active readiness = %+v, want ready/selectable", readiness)
	}
	if binding.Renderer != RendererArgoCD || binding.BaselineRepoID != "repo-1" || binding.CommitPolicy != string(types.CommitPolicyPullRequest) {
		t.Errorf("binding = %+v", binding)
	}
	snapshot.Cluster.State = types.ClusterStateRevoked
	_, readiness, err = p.Resolve(target, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if readiness.State.Selectable() {
		t.Errorf("revoked cluster readiness = %+v, want unavailable", readiness)
	}
	if _, _, err := p.ValidateSelection(target, json.RawMessage(`{"clusterId":"forged"}`)); err == nil {
		t.Fatal("deployment selection must reject arbitrary bindings")
	}
}

func validGrafanaConfig() json.RawMessage {
	return json.RawMessage(`{
		"baseUrl":"https://grafana.example/",
		"evaluation":"central",
		"folderPrefixes":["acme"],
		"datasources":[{"name":"metrics","type":"prometheus"}],
		"approval":{"required":true,"approverTeamIds":["team-1"]},
		"evidence":{"addonId":"addon-1"}
	}`)
}

func validGrafanaSnapshot() ResourceSnapshot {
	now := time.Now()
	return ResourceSnapshot{
		Cluster:      &types.Cluster{ID: "cluster:1", OrgID: "org:1", State: types.ClusterStateActive, LastSeenAt: &now},
		BaselineRepo: &types.TenantGitRepo{ID: "repo-1", OrgID: "org:1", Scope: types.GitRepoScopePlatform, BaseBranch: "main", CommitPolicy: types.CommitPolicyPullRequest},
		Addons: []*types.ClusterAddon{{
			ID: "addon-1", OrgID: "org:1", ClusterID: "cluster:1",
			DiscoveredMeta: json.RawMessage(`{"releaseName":"grafana","namespace":"monitoring"}`),
		}},
		Capabilities: []types.Capability{{
			ClusterID: "cluster:1", Kind: types.CapabilityKindHelmRelease, Name: "monitoring/grafana", Group: "helm.sh",
			UIHints: json.RawMessage(`{"status":"deployed"}`), LastSeenAt: now,
		}},
		TeamIDs: []string{"team-1"},
	}
}

func TestGrafanaProviderValidationAndResolution(t *testing.T) {
	p := grafanaProvider{}
	normalized, err := p.NormalizeConfig(validGrafanaConfig())
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(normalized, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["baseUrl"] != "https://grafana.example" {
		t.Errorf("normalized baseUrl = %v", cfg["baseUrl"])
	}
	if err := p.ValidateRegistration(validGrafanaSnapshot(), normalized); err != nil {
		t.Fatalf("valid registration: %v", err)
	}

	target := &Target{ResourceRef: ResourceRef{Kind: ResourceKindCluster, ID: "cluster:1"}, Config: normalized}
	binding, readiness, err := p.Resolve(target, validGrafanaSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if readiness.State != ReadinessReady || binding.BaselineRepoID != "repo-1" {
		t.Errorf("resolve readiness=%+v binding=%+v", readiness, binding)
	}
	selection, approval, err := p.ValidateSelection(target, json.RawMessage(`{"folder":"acme/team-a","datasource":"metrics","evaluation":"central"}`))
	if err != nil {
		t.Fatalf("valid selection: %v", err)
	}
	if !approval.Required || len(approval.ApproverTeamIDs) != 1 || len(selection) == 0 {
		t.Errorf("selection=%s approval=%+v", selection, approval)
	}
}

func TestGrafanaProviderRejectsUnsafeOrStaleInput(t *testing.T) {
	p := grafanaProvider{}
	for name, raw := range map[string]string{
		"secret field": `{"token":"secret"}`,
		"insecure URL": `{"baseUrl":"http://grafana.example"}`,
		"userinfo URL": `{"baseUrl":"https://user:pass@grafana.example"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.NormalizeConfig(json.RawMessage(raw)); err == nil {
				t.Fatal("expected validation error")
			} else {
				var validation *ValidationError
				if !errors.As(err, &validation) && !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("error = %T %v, want validation", err, err)
				}
			}
		})
	}

	badSnapshot := validGrafanaSnapshot()
	badSnapshot.Addons[0].ClusterID = "cluster:other"
	if err := p.ValidateRegistration(badSnapshot, validGrafanaConfig()); err == nil {
		t.Fatal("cross-cluster addon evidence must be rejected")
	}
	badSnapshot = validGrafanaSnapshot()
	badSnapshot.Capabilities[0].UIHints = json.RawMessage(`{"status":"failed"}`)
	if err := p.ValidateRegistration(badSnapshot, validGrafanaConfig()); err == nil {
		t.Fatal("non-deployed capability evidence must be rejected")
	}
	badSnapshot = validGrafanaSnapshot()
	badSnapshot.TeamIDs = nil
	if err := p.ValidateRegistration(badSnapshot, validGrafanaConfig()); err == nil {
		t.Fatal("unknown approver team must be rejected")
	}

	target := &Target{Config: validGrafanaConfig()}
	if _, _, err := p.ValidateSelection(target, json.RawMessage(`{"folder":"other/team","datasource":"metrics","evaluation":"central"}`)); err == nil {
		t.Fatal("folder outside policy must be rejected")
	}
	if _, _, err := p.ValidateSelection(target, json.RawMessage(`{"baseUrl":"https://evil.example"}`)); err == nil {
		t.Fatal("selection must reject arbitrary URL bindings")
	}
}
