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

type scaffolderStub struct{ name, version, displayName, digest string }

func (s *scaffolderStub) CreateRunExact(_ context.Context, _, _, name, version, displayName string, _ json.RawMessage, expectedDigest string) (*types.ScaffoldRun, []types.ScaffoldRunStep, bool, error) {
	s.name, s.version, s.displayName, s.digest = name, version, displayName, expectedDigest
	return &types.ScaffoldRun{ID: "run-1", TemplateDigest: expectedDigest}, nil, false, nil
}

func TestExecutorDelegatesExactCatalogAndTemplatePins(t *testing.T) {
	deployer := &deployerStub{}
	scaffolder := &scaffolderStub{}
	executor := NewExecutor(deployer, scaffolder)
	plan := &Plan{
		ID:     "dp-1",
		Source: Source{Kind: SourceCatalog, ItemID: "hiroba/payments-api", Version: "1.4.0"},
		App:    ArtifactPin{ItemID: "hiroba/payments-api", Version: "1.4.0", Digest: testDigest}, AppClusterID: "cluster-1",
		Deployment: DeploymentInput{Name: "payments", Namespace: "payments", OwnerTeam: "team-1", Spec: json.RawMessage(`{"replicas":2}`)},
	}
	execution, err := executor.Execute(context.Background(), "org-1", "user-1", plan)
	if err != nil || execution.InstanceID != "app-1" || execution.ScaffoldRunID != "" {
		t.Fatalf("execute = %#v, %v", execution, err)
	}
	if deployer.request.ItemID != plan.App.ItemID || deployer.request.Version != "1.4.0" || deployer.request.ClusterID != "cluster-1" || deployer.request.Requester != "user:user-1" {
		t.Fatalf("deploy request = %#v", deployer.request)
	}
	if deployer.request.ArtifactDigest != testDigest || deployer.request.DeploymentPlanID != "dp-1" {
		t.Fatalf("expected application/plan pins were not carried to execution: %#v", deployer.request)
	}
	plan.Source = Source{Kind: SourceTemplate, ItemID: "hiroba/service", Version: "1.4.0", DisplayName: "Payments"}
	execution, err = executor.Execute(context.Background(), "org-1", "user-1", plan)
	if err != nil || execution.InstanceID != "" || execution.ScaffoldRunID != "run-1" || scaffolder.name != "hiroba/service" || scaffolder.version != "1.4.0" || scaffolder.displayName != "Payments" || scaffolder.digest != testDigest {
		t.Fatalf("template execute = %#v, %v, scaffold %#v", execution, err, scaffolder)
	}
}
