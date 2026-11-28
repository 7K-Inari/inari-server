//go:build integration

package tenancy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/planlimits"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type staticBrokerLimits struct{}

func (staticBrokerLimits) PlanLimits(context.Context, string) (planlimits.Limits, error) {
	return planlimits.Limits{}, nil
}

type recordingBrokerManager struct{ calls int }

func (m *recordingBrokerManager) CreateIdP(context.Context, tenancy.BrokerIdPSpec) error {
	m.calls++
	return nil
}
func (m *recordingBrokerManager) UpdateIdP(context.Context, tenancy.BrokerIdPSpec) error {
	m.calls++
	return nil
}
func (m *recordingBrokerManager) DeleteIdP(context.Context, string) error { m.calls++; return nil }
func (m *recordingBrokerManager) LinkIdPToOrg(context.Context, string, string) error {
	m.calls++
	return nil
}
func (m *recordingBrokerManager) UnlinkIdPFromOrg(context.Context, string, string) error {
	m.calls++
	return nil
}
func (m *recordingBrokerManager) SetOrgDomains(context.Context, string, []string) error {
	m.calls++
	return nil
}

func TestIdPBrokeringHonorsPlanLimit(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	manager := &recordingBrokerManager{}
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore()).
		WithPlanLimitsProvider(staticBrokerLimits{}).
		WithIdentityProviderManager(manager)
	if _, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	input := &types.BrokeredIdP{Alias: "sso", IssuerURL: "https://idp.example.com", ClientID: "inari-acme"}
	_, err := svc.CreateBrokeredIdP(ctx, "user-1", "acme", input, "secret")
	var denied *planlimits.LimitExceededError
	if !errors.As(err, &denied) || denied.Limit != planlimits.GateIdPBrokering {
		t.Fatalf("create error = %T %+v", err, err)
	}
	if err := svc.UpdateBrokeredIdP(ctx, "user-1", "acme", input, "secret"); !errors.As(err, &denied) {
		t.Fatalf("update error = %T %+v", err, err)
	}
	if manager.calls != 0 {
		t.Fatalf("denied brokering reached Keycloak %d times", manager.calls)
	}
}
