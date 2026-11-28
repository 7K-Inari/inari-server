package tenantzonefactory

import (
	"context"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/planlimits"
	"github.com/7K-Inari/inari-server/internal/types"
)

type recordingLimitsProjection struct {
	tenantID string
	limits   planlimits.Limits
	calls    int
}

func (p *recordingLimitsProjection) PutPlanLimits(_ context.Context, tenantID string, limits planlimits.Limits) error {
	p.calls++
	p.tenantID = tenantID
	p.limits = limits
	return nil
}

func TestWireZonePropagatesOwnerLimitsToChild(t *testing.T) {
	projection := &recordingLimitsProjection{}
	evaluator := planlimits.NewEvaluator(planlimits.ProviderFunc(func(_ context.Context, tenantID string) (planlimits.Limits, error) {
		if tenantID != "org:platform" {
			t.Fatalf("evaluated tenant = %q, want owner", tenantID)
		}
		return planlimits.Limits{AllFeatures: true}, nil
	}), "")
	w := &ModuleWiring{
		Tenants: &qaTenantCreator{}, Clusters: &qaClusters{}, Accounts: &qaAccounts{}, Git: gitprovider.NewFake(),
		Agent:          AgentInstallParams{ImageRepo: "img", GatewayAddress: "https://gw"},
		LimitEvaluator: evaluator, LimitsProjection: projection,
	}
	zone := &types.TenantZone{Slug: "acme", DisplayName: "Acme", OwnerOrgID: "org:platform", Region: "eu-west-1", Tier: "starter"}
	if _, err := w.WireZone(context.Background(), zone, "arn:role"); err != nil {
		t.Fatal(err)
	}
	if projection.calls != 1 || projection.tenantID != "org-acme" || !projection.limits.AllFeatures {
		t.Fatalf("child projection = %+v", projection)
	}
}
