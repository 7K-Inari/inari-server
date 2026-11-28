package approvals

import (
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/planlimits"
	"github.com/7K-Inari/inari-server/internal/types"
)

func deniedEvaluator(gate string) planlimits.Evaluator {
	return planlimits.NewEvaluator(planlimits.ProviderFunc(func(context.Context, string) (planlimits.Limits, error) {
		return planlimits.Limits{FeatureGates: map[string]bool{gate: false}}, nil
	}), "")
}

func TestApprovalRequiredGateHonorsPlanLimit(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil).WithLimitEvaluator(deniedEvaluator(planlimits.GateApprovals))
	_, err := svc.Gate(context.Background(), GateInput{
		OrgID: "org:1",
		Item:  &types.CatalogItem{ApprovalPolicy: types.ApprovalPolicyPeer},
	})
	var denied *planlimits.LimitExceededError
	if !errors.As(err, &denied) || denied.Limit != planlimits.GateApprovals {
		t.Fatalf("approval gate error = %T %+v", err, err)
	}

	auto := NewService(nil, nil, nil, nil, nil).WithLimitEvaluator(deniedEvaluator(planlimits.GateApprovals))
	result, err := auto.Gate(context.Background(), GateInput{OrgID: "org:1", Item: &types.CatalogItem{ApprovalPolicy: types.ApprovalPolicyAuto}})
	if err != nil || result == nil || !result.Approved {
		t.Fatalf("auto action must not require the paid gate: result=%+v err=%v", result, err)
	}
}

func TestApprovalConfigUpdateHonorsPlanLimit(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil).WithLimitEvaluator(deniedEvaluator(planlimits.GateApprovals))
	_, err := svc.UpdateConfig(context.Background(), "user-1", "org:1", DefaultConfig())
	var denied *planlimits.LimitExceededError
	if !errors.As(err, &denied) {
		t.Fatalf("config update error = %T %+v", err, err)
	}
}
