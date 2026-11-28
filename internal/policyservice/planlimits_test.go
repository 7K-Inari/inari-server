package policyservice

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/planlimits"
	"github.com/7K-Inari/inari-server/internal/types"
)

func policyPackDeniedEvaluator() planlimits.Evaluator {
	return planlimits.NewEvaluator(planlimits.ProviderFunc(func(context.Context, string) (planlimits.Limits, error) {
		return planlimits.Limits{}, nil
	}), "")
}

func TestPolicyPackMutationsHonorPlanLimit(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil).WithLimitEvaluator(policyPackDeniedEvaluator())
	_, err := svc.CreatePolicyPack(context.Background(), "user-1", "org:1", "baseline", types.PolicyPackEngineKyverno, "", "1.0.0", nil, json.RawMessage(`[{"apiVersion":"v1"}]`))
	var denied *planlimits.LimitExceededError
	if !errors.As(err, &denied) || denied.Limit != planlimits.GatePolicyPacks {
		t.Fatalf("create error = %T %+v", err, err)
	}
	_, err = svc.Assign(context.Background(), "user-1", "org:1", "policypack:1", "cluster", "cluster:1")
	if !errors.As(err, &denied) {
		t.Fatalf("assign error = %T %+v", err, err)
	}
}

func TestPolicyPackDistributionSkipsDisabledTenant(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil).WithLimitEvaluator(policyPackDeniedEvaluator())
	handler := NewDistributeHandler(svc, nil)
	payload, _ := json.Marshal(types.PolicyPackAssignedPayload{OrgID: "org:1", PackID: "policypack:1", TargetType: "cluster", TargetID: "cluster:1"})
	if err := handler.Handle(context.Background(), &types.OutboxEvent{Payload: payload}); err != nil {
		t.Fatalf("disabled distribution must be a benign skip: %v", err)
	}
}
