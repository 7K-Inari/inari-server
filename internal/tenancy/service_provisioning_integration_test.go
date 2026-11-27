//go:build integration

package tenancy_test

import (
	"context"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/tenancy"
)

type ensureFakeIDP struct{ *fakeIdP }

func (f *ensureFakeIDP) EnsureOrganization(ctx context.Context, alias, displayName string) (string, error) {
	f.mu.Lock()
	for id, existing := range f.orgs {
		if existing == alias {
			f.mu.Unlock()
			return id, nil
		}
	}
	f.mu.Unlock()
	return f.CreateOrganization(ctx, alias, displayName)
}

func TestProvisionTenantIsActorFreeAndReplayable(t *testing.T) {
	ctx := context.Background()
	database := setupDB(t)
	idp := &ensureFakeIDP{newFakeIdP()}
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	org, teams, err := svc.ProvisionTenant(ctx, "service-account-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(teams) != 4 {
		t.Fatalf("teams = %d, want 4", len(teams))
	}
	if got := len(idp.orgMembers[org.KeycloakOrgID]); got != 0 {
		t.Fatalf("service account joined organization %d times", got)
	}
	for team, members := range idp.grpMembers {
		if len(members) != 0 {
			t.Fatalf("service account joined %s: %v", team, members)
		}
	}
	var memberships int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE org_id = $1`, org.ID).Scan(&memberships); err != nil {
		t.Fatal(err)
	}
	if memberships != 0 {
		t.Fatalf("memberships = %d", memberships)
	}
	replayed, replayedTeams, err := svc.ProvisionTenant(ctx, "service-account-1", "acme", "Acme")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replayed.ID != org.ID || len(replayedTeams) != 4 {
		t.Fatalf("replay returned different tenant: %+v", replayed)
	}
	var bootstrapEvents int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE org_id = $1 AND event_type = 'tenant.created'`, org.ID).Scan(&bootstrapEvents); err != nil {
		t.Fatal(err)
	}
	if bootstrapEvents != 1 {
		t.Fatalf("tenant.created events = %d", bootstrapEvents)
	}
}
