package fleetmanager

import (
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/planlimits"
	"github.com/7K-Inari/inari-server/internal/types"
)

func fleetDeniedEvaluator() planlimits.Evaluator {
	return planlimits.NewEvaluator(planlimits.ProviderFunc(func(context.Context, string) (planlimits.Limits, error) {
		return planlimits.Limits{}, nil
	}), "")
}

func TestFleetRolloutMutationsHonorPlanLimit(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil).WithLimitEvaluator(fleetDeniedEvaluator())
	_, err := svc.CreateRollout(context.Background(), "user-1", "org:1", CreateRolloutInput{
		Name: "fleet", Kind: types.RolloutKindAgentUpgrade, TargetRef: "agent", DesiredVersion: "1.0.0",
		Stages: []types.RolloutStage{{Name: "canary", ClusterSetIDs: []string{"clusterset:1"}, MaxConcurrency: "1"}},
	})
	var denied *planlimits.LimitExceededError
	if !errors.As(err, &denied) || denied.Limit != planlimits.GateFleetRollouts {
		t.Fatalf("create error = %T %+v", err, err)
	}
	if _, err := svc.StartRollout(context.Background(), "user-1", "org:1", "rollout:1"); !errors.As(err, &denied) {
		t.Fatalf("start error = %T %+v", err, err)
	}
	if _, err := svc.ResumeRollout(context.Background(), "user-1", "org:1", "rollout:1"); !errors.As(err, &denied) {
		t.Fatalf("resume error = %T %+v", err, err)
	}
	if _, err := svc.Rollback(context.Background(), "user-1", "org:1", "rollout:1", "0.9.0"); !errors.As(err, &denied) {
		t.Fatalf("rollback error = %T %+v", err, err)
	}
}

func TestDriftReportingSkipsDisabledTenant(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil).WithLimitEvaluator(fleetDeniedEvaluator())
	created, err := svc.ReportDrift(context.Background(), &types.DriftEvent{OrgID: "org:1", ClusterID: "cluster:1", Kind: types.DriftKindInstanceSpec})
	if err != nil || created {
		t.Fatalf("disabled drift report: created=%v err=%v", created, err)
	}
}
