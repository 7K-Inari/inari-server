//go:build integration

package cloudaccounts_test

import (
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/planlimits"
	"github.com/7K-Inari/inari-server/internal/types"
)

type staticCloudLimits struct{ allFeatures bool }

func (p staticCloudLimits) PlanLimits(context.Context, string) (planlimits.Limits, error) {
	return planlimits.Limits{AllFeatures: p.allFeatures}, nil
}

func TestCloudAccountPlatformContextRequiresZoneVending(t *testing.T) {
	svc := itService(itDB(t), fakeValidator{}).WithPlanLimitsProvider(staticCloudLimits{})
	input := itInput
	input.RunContext = types.CloudAccountRunContextPlatform
	_, err := svc.Register(context.Background(), "user-1", "org:1", input)
	var denied *planlimits.LimitExceededError
	if !errors.As(err, &denied) || denied.Limit != planlimits.GateZoneVending {
		t.Fatalf("platform account error = %T %+v", err, err)
	}

	input.RunContext = types.CloudAccountRunContextTenant
	if _, err := svc.Register(context.Background(), "user-1", "org:1", input); err != nil {
		t.Fatalf("BYO account must remain available: %v", err)
	}

	allFeaturesService := itService(itDB(t), fakeValidator{}).WithPlanLimitsProvider(staticCloudLimits{allFeatures: true})
	input.RunContext = types.CloudAccountRunContextPlatform
	if _, err := allFeaturesService.Register(context.Background(), "user-1", "org:1", input); err != nil {
		t.Fatalf("all-features account registration denied: %v", err)
	}
}
