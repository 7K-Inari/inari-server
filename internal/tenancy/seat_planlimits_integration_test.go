//go:build integration

package tenancy_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/planlimits"
	"github.com/7K-Inari/inari-server/internal/tenancy"
)

type staticSeatLimits struct{ maximum int64 }

func (p staticSeatLimits) PlanLimits(context.Context, string) (planlimits.Limits, error) {
	return planlimits.Limits{MaxDeveloperSeats: &p.maximum}, nil
}

func TestDeveloperSeatLimitDeniesOnlyNewMembers(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	idp.users["user-1"] = true
	idp.users["user-2"] = true
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore()).
		WithPlanLimitsProvider(staticSeatLimits{maximum: 1})
	if _, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}

	err := svc.AddMember(ctx, "user-1", "acme", "developers", "user-2")
	var denied *planlimits.LimitExceededError
	if !errors.As(err, &denied) || denied.Limit != planlimits.LimitDeveloperSeats {
		t.Fatalf("new member denial = %T %+v", err, err)
	}
	if denied.CurrentUsage == nil || *denied.CurrentUsage != 1 || denied.MaxAllowed == nil || *denied.MaxAllowed != 1 {
		t.Fatalf("seat usage = %+v", denied)
	}
	for _, members := range idp.orgMembers {
		if len(members) != 1 || members[0] != "user-1" {
			t.Fatalf("denied invite mutated Keycloak: %+v", members)
		}
	}

	if err := svc.SetMemberRole(ctx, "user-1", "acme", "user-1", "admin"); err != nil {
		t.Fatalf("existing member must remain manageable at cap: %v", err)
	}
}

func TestDeveloperSeatLimitConcurrentInvites(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	idp.users["user-1"] = true
	for i := 0; i < 6; i++ {
		idp.users[string(rune('a'+i))] = true
	}
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore()).
		WithPlanLimitsProvider(staticSeatLimits{maximum: 3})
	if _, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- svc.AddMember(ctx, "user-1", "acme", "developers", string(rune('a'+i)))
		}(i)
	}
	wg.Wait()
	close(errs)
	created := 0
	for err := range errs {
		if err == nil {
			created++
			continue
		}
		var denied *planlimits.LimitExceededError
		if !errors.As(err, &denied) {
			t.Fatalf("unexpected invite error: %v", err)
		}
	}
	if created != 2 {
		t.Fatalf("new seats = %d, want 2", created)
	}
}
