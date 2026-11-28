package planlimits

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

type providerFunc func(context.Context, string) (Limits, error)

func (f providerFunc) PlanLimits(ctx context.Context, tenantID string) (Limits, error) {
	return f(ctx, tenantID)
}

func TestEvaluationChecksNumericLimitsAndPresence(t *testing.T) {
	two := int64(2)
	zero := int64(0)
	evaluator := NewEvaluator(providerFunc(func(context.Context, string) (Limits, error) {
		return Limits{MaxClusters: &two, MaxDeveloperSeats: &zero}, nil
	}), "https://7kgroup.org")
	evaluation, err := evaluator.Evaluate(context.Background(), "org:kc-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluation.CheckQuota(LimitClusters, 1); err != nil {
		t.Fatalf("usage below cap denied: %v", err)
	}
	err = evaluation.CheckQuota(LimitClusters, 2)
	var limitErr *LimitExceededError
	if !errors.As(err, &limitErr) {
		t.Fatalf("cap error = %T %v", err, err)
	}
	if limitErr.GetStatus() != http.StatusTooManyRequests || limitErr.Code != "plan_limit_exceeded" || limitErr.Limit != LimitClusters || limitErr.LimitKind != "quota" {
		t.Fatalf("unexpected error contract: %+v", limitErr)
	}
	if limitErr.CurrentUsage == nil || *limitErr.CurrentUsage != 2 || limitErr.MaxAllowed == nil || *limitErr.MaxAllowed != 2 || limitErr.Requested == nil || *limitErr.Requested != 1 {
		t.Fatalf("usage was not preserved: %+v", limitErr)
	}
	if limitErr.UpgradeURL != "https://7kgroup.org" {
		t.Fatalf("upgrade URL = %q", limitErr.UpgradeURL)
	}
	if err := evaluation.CheckQuota(LimitDeveloperSeats, 0); !errors.As(err, &limitErr) {
		t.Fatalf("present zero must deny: %v", err)
	}
}

func TestEvaluationChecksFeaturesAndUnlimited(t *testing.T) {
	evaluation, err := NewEvaluator(providerFunc(func(context.Context, string) (Limits, error) {
		return Limits{FeatureGates: map[string]bool{GateApprovals: true, GatePolicyPacks: false}}, nil
	}), "").Evaluate(context.Background(), "org:kc-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluation.CheckFeature(GateApprovals); err != nil {
		t.Fatalf("enabled gate denied: %v", err)
	}
	for _, gate := range []string{GatePolicyPacks, GateZoneVending} {
		err := evaluation.CheckFeature(gate)
		var limitErr *LimitExceededError
		if !errors.As(err, &limitErr) || limitErr.GetStatus() != http.StatusForbidden || limitErr.LimitKind != "feature" || limitErr.Limit != gate {
			t.Fatalf("gate %q error = %+v", gate, err)
		}
	}

	unlimited, err := NewEvaluator(nil, "").Evaluate(context.Background(), "org:any")
	if err != nil {
		t.Fatal(err)
	}
	if err := unlimited.CheckQuota(LimitClusters, 1_000_000); err != nil {
		t.Fatalf("OSS numeric default = %v", err)
	}
	if err := unlimited.CheckFeature(GateZoneVending); err != nil {
		t.Fatalf("OSS feature default = %v", err)
	}
}

func TestEvaluationProviderFailureIsNotLimitExceeded(t *testing.T) {
	_, err := NewEvaluator(providerFunc(func(context.Context, string) (Limits, error) {
		return Limits{}, errors.New("keycloak unavailable")
	}), "").Evaluate(context.Background(), "org:kc-1")
	var unavailable *LimitsUnavailableError
	if !errors.As(err, &unavailable) || unavailable.GetStatus() != http.StatusServiceUnavailable || unavailable.Code != "plan_limits_unavailable" {
		t.Fatalf("provider error = %T %+v", err, err)
	}
	var limitErr *LimitExceededError
	if errors.As(err, &limitErr) {
		t.Fatal("provider outage became a plan denial")
	}
}

func TestLimitErrorJSONIncludesZeroUsage(t *testing.T) {
	evaluation, err := NewEvaluator(providerFunc(func(context.Context, string) (Limits, error) {
		zero := int64(0)
		return Limits{MaxClusters: &zero}, nil
	}), "").Evaluate(context.Background(), "org:kc-1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(evaluation.CheckQuota(LimitClusters, 0))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["currentUsage"] != float64(0) || body["maxAllowed"] != float64(0) || body["requested"] != float64(1) {
		t.Fatalf("zero values were omitted: %s", raw)
	}
}
