package deploymentplan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/types"
)

type Deployer interface {
	Deploy(ctx context.Context, req orchestrator.DeployRequest) (*orchestrator.DeployResult, error)
}

type Scaffolder interface {
	CreateRun(ctx context.Context, actor, orgID, name, version, displayName string, values json.RawMessage) (*types.ScaffoldRun, []types.ScaffoldRunStep, bool, error)
}

type Execution struct {
	InstanceID    string
	ScaffoldRunID string
	CommitSHA     string
	PRURL         string
	ApprovalID    string
}

type Executor struct {
	deployer   Deployer
	scaffolder Scaffolder
}

func NewExecutor(deployer Deployer, scaffolder Scaffolder) *Executor {
	return &Executor{deployer: deployer, scaffolder: scaffolder}
}

func (e *Executor) Execute(ctx context.Context, orgID, subject string, plan *Plan) (*Execution, error) {
	switch plan.Source.Kind {
	case SourceCatalog, SourceChart:
		if e.deployer == nil {
			return nil, errors.New("catalog deployer is not configured")
		}
		result, err := e.deployer.Deploy(ctx, orchestrator.DeployRequest{
			OrgID: orgID, ClusterID: plan.AppClusterID, ItemID: plan.App.ItemID, Version: plan.App.Version,
			Name: plan.Deployment.Name, Namespace: plan.Deployment.Namespace, OwnerTeam: plan.Deployment.OwnerTeam,
			Spec: plan.Deployment.Spec, Requester: "user:" + strings.TrimPrefix(subject, "user:"), RepoID: plan.Deployment.RepoID,
			ArtifactDigest: plan.App.Digest,
		})
		if err != nil {
			return nil, err
		}
		return &Execution{InstanceID: result.InstanceID, CommitSHA: result.CommitSHA, PRURL: result.PRURL, ApprovalID: result.ApprovalID}, nil
	case SourceTemplate:
		if e.scaffolder == nil {
			return nil, errors.New("template scaffolder is not configured")
		}
		displayName := plan.Source.DisplayName
		if displayName == "" {
			displayName = plan.Deployment.DisplayName
		}
		run, _, _, err := e.scaffolder.CreateRun(ctx, subject, orgID, plan.Source.ItemID, plan.Source.Version, displayName, plan.Deployment.Spec)
		if err != nil {
			return nil, err
		}
		return &Execution{ScaffoldRunID: run.ID}, nil
	default:
		return nil, errors.New("unsupported application source")
	}
}
