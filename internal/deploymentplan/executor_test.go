package deploymentplan

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/types"
)

type deployerStub struct{ request orchestrator.DeployRequest }

func (d *deployerStub) Deploy(_ context.Context, req orchestrator.DeployRequest) (*orchestrator.DeployResult, error) {
	d.request = req
	return &orchestrator.DeployResult{InstanceID: "app-1"}, nil
}

type scaffolderStub struct{ name, version, displayName string }

func (s *scaffolderStub) CreateRun(_ context.Context, _, _, name, version, displayName string, _ json.RawMessage) (*types.ScaffoldRun, []types.ScaffoldRunStep, bool, error) {
	s.name, s.version, s.displayName = name, version, displayName
	return &types.ScaffoldRun{ID: "run-1"}, nil, false, nil
}

func TestExecutorDelegatesExactCatalogAndTemplatePins(t *testing.T) {
	deployer := &deployerStub{}
	scaffolder := &scaffolderStub{}
	executor := NewExecutor(deployer, scaffolder)
	plan := &Plan{
		Source: Source{Kind: SourceCatalog, ItemID: "hiroba/payments-api", Version: "1.4.0"},
		App:    ArtifactPin{ItemID: "hiroba/payments-api", Version: "1.4.0"}, AppClusterID: "cluster-1",
		Deployment: DeploymentInput{Name: "payments", Namespace: "payments", OwnerTeam: "team-1", Spec: json.RawMessage(`{"replicas":2}`)},
	}
	instanceID, runID, err := executor.Execute(context.Background(), "org-1", "user-1", plan)
	if err != nil || instanceID != "app-1" || runID != "" {
		t.Fatalf("execute = %q %q %v", instanceID, runID, err)
	}
	if deployer.request.ItemID != plan.App.ItemID || deployer.request.Version != "1.4.0" || deployer.request.ClusterID != "cluster-1" || deployer.request.Requester != "user:user-1" {
		t.Fatalf("deploy request = %#v", deployer.request)
	}
	plan.Source = Source{Kind: SourceTemplate, ItemID: "hiroba/service", Version: "1.4.0", DisplayName: "Payments"}
	instanceID, runID, err = executor.Execute(context.Background(), "org-1", "user-1", plan)
	if err != nil || instanceID != "" || runID != "run-1" || scaffolder.name != "hiroba/service" || scaffolder.version != "1.4.0" || scaffolder.displayName != "Payments" {
		t.Fatalf("template execute = %q %q %v, scaffold %#v", instanceID, runID, err, scaffolder)
	}
}
