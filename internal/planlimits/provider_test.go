package planlimits

import (
	"context"
	"errors"
	"testing"
	"time"
)

type attributesReaderFunc func(context.Context, string) (map[string][]string, error)

func (f attributesReaderFunc) OrganizationAttributes(ctx context.Context, id string) (map[string][]string, error) {
	return f(ctx, id)
}

func TestUnlimitedProvider(t *testing.T) {
	limits, err := (UnlimitedProvider{}).PlanLimits(context.Background(), "org:any")
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxClusters != nil || limits.MaxDeveloperSeats != nil || !limits.AllFeatures {
		t.Fatalf("OSS default is not unlimited: %+v", limits)
	}
}

func TestKeycloakProviderParsesPresence(t *testing.T) {
	provider := NewKeycloakProvider(attributesReaderFunc(func(_ context.Context, id string) (map[string][]string, error) {
		if id != "kc-1" {
			t.Fatalf("keycloak id = %q", id)
		}
		return map[string][]string{KeycloakPlanLimitsAttribute: {`{"maxClusters":0,"allFeatures":false,"featureGates":{"policy-packs":true}}`}}, nil
	}))
	limits, err := provider.PlanLimits(context.Background(), "org:kc-1")
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxClusters == nil || *limits.MaxClusters != 0 || limits.MaxDeveloperSeats != nil {
		t.Fatalf("presence lost: %+v", limits)
	}
	if !limits.FeatureGates["policy-packs"] || limits.AllFeatures {
		t.Fatalf("feature gates lost: %+v", limits)
	}
}

func TestKeycloakProviderRejectsMissingMalformedAndBadTenant(t *testing.T) {
	missing := NewKeycloakProvider(attributesReaderFunc(func(context.Context, string) (map[string][]string, error) {
		return nil, nil
	}))
	if _, err := missing.PlanLimits(context.Background(), "org:kc-1"); !errors.Is(err, ErrLimitsNotFound) {
		t.Fatalf("missing error = %v", err)
	}
	malformed := NewKeycloakProvider(attributesReaderFunc(func(context.Context, string) (map[string][]string, error) {
		return map[string][]string{KeycloakPlanLimitsAttribute: {`{"maxClusters":-1}`}}, nil
	}))
	if _, err := malformed.PlanLimits(context.Background(), "org:kc-1"); err == nil {
		t.Fatal("accepted negative limits")
	}
	if _, err := missing.PlanLimits(context.Background(), "user:kc-1"); !errors.Is(err, ErrInvalidTenantID) {
		t.Fatalf("tenant error = %v", err)
	}
}

func TestMeteringValidationAndNoop(t *testing.T) {
	valid := MeteringEvent{EventID: "evt-1", TenantID: "org:1", MetricName: "clusters.active", Value: -1, OccurredAt: time.Now()}
	if err := ValidateMeteringEvent(valid); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	invalid := valid
	invalid.MetricName = "bad metric"
	if err := ValidateMeteringEvent(invalid); err == nil {
		t.Fatal("accepted malformed metric")
	}
	invalid = valid
	invalid.OccurredAt = time.Time{}
	if err := ValidateMeteringEvent(invalid); err == nil {
		t.Fatal("accepted missing timestamp")
	}
	if err := (NoopMeteringEmitter{}).EmitMeteringEvent(context.Background(), MeteringEvent{}); err != nil {
		t.Fatal(err)
	}
}
