//go:build integration

package tenantzonefactory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/7K-Inari/inari-server/internal/planlimits"
	"github.com/7K-Inari/inari-server/internal/types"
)

type staticZoneLimits struct{ allFeatures bool }

func (p staticZoneLimits) PlanLimits(context.Context, string) (planlimits.Limits, error) {
	return planlimits.Limits{AllFeatures: p.allFeatures}, nil
}

const zoneRequestBody = `{"slug":"acme-dev","displayName":"Acme Dev","ouId":"ou-1","region":"eu-west-1","tier":"starter","tags":{"cost-center":"cc-1"},"managementAccountId":"ca:mgmt"}`

func TestZoneVendingDeniedWithoutFeature(t *testing.T) {
	f := newITFixture(t, false)
	defer f.srv.Close()
	f.svc.WithPlanLimitsProvider(staticZoneLimits{})
	code, body := f.req(t, http.MethodPost, "/api/v1/tenants/platform/zones", zoneRequestBody)
	if code != http.StatusForbidden {
		t.Fatalf("request zone = %d %s, want 403", code, body)
	}
	if len(f.aws.CreatedAccounts()) != 0 || f.wiring.wired != 0 {
		t.Fatal("denied zone vending produced external work")
	}
}

func TestZoneVendingAllowedAndRecheckedOnResume(t *testing.T) {
	f := newITFixture(t, true)
	defer f.srv.Close()
	f.svc.WithPlanLimitsProvider(staticZoneLimits{allFeatures: true})
	code, body := f.req(t, http.MethodPost, "/api/v1/tenants/platform/zones", zoneRequestBody)
	if code != http.StatusOK {
		t.Fatalf("all-features request = %d %s", code, body)
	}
	var out struct {
		Zone types.TenantZone `json:"zone"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}

	f.svc.WithPlanLimitsProvider(staticZoneLimits{})
	err := f.svc.StartProvisioning(context.Background(), out.Zone.ID, "user-1")
	var denied *planlimits.LimitExceededError
	if !errors.As(err, &denied) || denied.Limit != planlimits.GateZoneVending {
		t.Fatalf("resume denial = %T %+v", err, err)
	}
	if len(f.aws.CreatedAccounts()) != 0 {
		t.Fatal("denied resume reached AWS")
	}
}
