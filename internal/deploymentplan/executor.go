package deploymentplan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/types"
)

type Deployer interface {
	Deploy(ctx context.Context, req orchestrator.DeployRequest) (*orchestrator.DeployResult, error)
}

type Scaffolder interface {
	CreateRunExact(ctx context.Context, actor, orgID, name, version, displayName string, values json.RawMessage, expectedDigest string) (*types.ScaffoldRun, []types.ScaffoldRunStep, bool, error)
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

// RevalidateApprovedExecution reruns the common plan's full submit validation
// through the existing idempotency boundary. An existing key returns before
// CreatePlan/Execute, so this is read-only and cannot duplicate the app.
func (s *Service) RevalidateApprovedExecution(ctx context.Context, orgID, planID, requester string) error {
	plan, err := s.store.GetPlan(ctx, orgID, planID)
	if err != nil {
		return err
	}
	if strings.TrimPrefix(requester, "user:") != strings.TrimPrefix(plan.Requester, "user:") {
		return fmt.Errorf("%w: approval requester does not own deployment plan", ErrPlanConflict)
	}
	source := plan.Source
	request := PlanRequest{Operation: plan.Operation, Source: &source, Deployment: plan.Deployment,
		Observability: plan.Observability, PlanFingerprint: plan.PlanFingerprint, IdempotencyKey: plan.IdempotencyKey}
	_, err = s.Submit(ctx, request, orgID, plan.OrgSlug, plan.Requester)
	return err
}

// LinkApprovedExecution records only the real orchestrator result. It never
// creates a companion instance or advances rendering across the external gate.
func (s *Service) LinkApprovedExecution(ctx context.Context, orgID, planID string, result *orchestrator.DeployResult) error {
	if result == nil || result.InstanceID == "" {
		return errors.New("approved execution returned no application instance")
	}
	plan, err := s.store.GetPlan(ctx, orgID, planID)
	if err != nil {
		return err
	}
	plan.AppInstanceID = result.InstanceID
	if result.CommitSHA != "" {
		plan.CommitSHA = result.CommitSHA
	}
	if result.PRURL != "" {
		plan.PRURL = result.PRURL
	}
	plan.State = result.Status
	if plan.State == "" {
		plan.State = "submitted"
	}
	plan.ErrorCode, plan.ErrorMessage = "", ""
	plan.UpdatedAt = s.now()
	if plan.Companion != nil {
		plan.Companion.AppInstanceID = result.InstanceID
		plan.Companion.UpdatedAt = plan.UpdatedAt
		if plan.Companion.State == "waiting_for_app" && s.gate.CompanionRendering {
			plan.Companion.State = "render_pending"
		}
	}
	return s.store.UpdatePlan(ctx, plan)
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
			ArtifactDigest: plan.App.Digest, DeploymentPlanID: plan.ID,
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
		run, _, _, err := e.scaffolder.CreateRunExact(ctx, subject, orgID, plan.Source.ItemID, plan.Source.Version, displayName, plan.Deployment.Spec, plan.App.Digest)
		if err != nil {
			return nil, err
		}
		if run == nil || run.TemplateDigest != plan.App.Digest {
			return nil, fmt.Errorf("%w: scaffold run template digest differs from reviewed plan", ErrPlanConflict)
		}
		return &Execution{ScaffoldRunID: run.ID}, nil
	default:
		return nil, errors.New("unsupported application source")
	}
}
