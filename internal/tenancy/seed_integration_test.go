//go:build integration

package tenancy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/tenancy"
)

// TestSeedPlatformOrg proves the reserved platform org is seeded end-to-end:
// Keycloak org + DB projection + default teams/groups + audit, with no
// creator membership (ADR-0005).
func TestSeedPlatformOrg(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())

	if err := svc.SeedPlatformOrg(ctx); err != nil {
		t.Fatalf("SeedPlatformOrg: %v", err)
	}

	org, err := svc.GetTenant(ctx, tenancy.PlatformOrgSlug)
	if err != nil {
		t.Fatalf("GetTenant(platform): %v", err)
	}
	if !strings.HasPrefix(org.ID, "org:kc-platform") {
		t.Errorf("org.ID = %q, want org:kc-platform-*", org.ID)
	}
	teams, err := svc.ListTeams(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(teams) != 3 {
		t.Fatalf("teams = %d, want 3", len(teams))
	}
	var paths []string
	for _, tm := range teams {
		paths = append(paths, tm.KeycloakGroupPath)
	}
	for _, want := range []string{"tenant-platform/platform-team", "tenant-platform/developers", "tenant-platform/viewers"} {
		found := false
		for _, p := range paths {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing group path %q in %v", want, paths)
		}
	}
	if len(idp.groups) != 3 {
		t.Errorf("keycloak groups created = %v", idp.groups)
	}

	// No creator membership: seeding is actor-free.
	if got := idp.orgMembers[org.KeycloakOrgID]; len(got) != 0 {
		t.Errorf("org members = %v, want none", got)
	}
	if len(idp.grpMembers) != 0 {
		t.Errorf("group members = %v, want none", idp.grpMembers)
	}

	// Audit rows: 3 teams + 1 tenant, actor system:seed.
	events, err := audit.NewStore().List(ctx, database.Pool, org.ID, 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("audit events = %d, want 4", len(events))
	}
	for _, ev := range events {
		if ev.Actor != "system:seed" {
			t.Errorf("audit actor = %q, want system:seed", ev.Actor)
		}
	}
}

// TestSeedPlatformOrgIdempotent proves a second seed is a no-op: no duplicate
// Keycloak org, groups, teams, or audit rows.
func TestSeedPlatformOrgIdempotent(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())

	if err := svc.SeedPlatformOrg(ctx); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if err := svc.SeedPlatformOrg(ctx); err != nil {
		t.Fatalf("second seed: %v", err)
	}

	var orgs int
	for _, alias := range idp.orgs {
		if alias == tenancy.PlatformOrgSlug {
			orgs++
		}
	}
	if orgs != 1 {
		t.Errorf("keycloak orgs with alias platform = %d, want 1", orgs)
	}
	if len(idp.groups) != 3 {
		t.Errorf("keycloak groups = %v, want 3", idp.groups)
	}
	org, err := svc.GetTenant(ctx, tenancy.PlatformOrgSlug)
	if err != nil {
		t.Fatal(err)
	}
	teams, err := svc.ListTeams(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(teams) != 3 {
		t.Errorf("teams = %d, want 3", len(teams))
	}
	events, err := audit.NewStore().List(ctx, database.Pool, org.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Errorf("audit events = %d, want 4 (no duplicates)", len(events))
	}
}

// TestSeedPlatformOrgClusterRegistration proves a cluster registers under the
// seeded platform org exactly like any tenant org (scope item 1: no
// clusterregistry/agentgateway changes needed).
func TestSeedPlatformOrgClusterRegistration(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	if err := svc.SeedPlatformOrg(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	org, err := svc.GetTenant(ctx, tenancy.PlatformOrgSlug)
	if err != nil {
		t.Fatal(err)
	}

	registry := clusterregistry.NewService(database, nil, clusterregistry.NewStore(), audit.NewStore(), 0, false)
	cluster, err := registry.CreateCluster(ctx, "system:seed", org.ID, "7kgroup-platform", nil)
	if err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}
	if cluster.OrgID != org.ID {
		t.Errorf("cluster.OrgID = %q, want %q", cluster.OrgID, org.ID)
	}
	plaintext, tok, err := registry.IssueToken(ctx, "system:seed", cluster.ID)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if plaintext == "" || tok.ClusterID != cluster.ID {
		t.Errorf("token = %+v", tok)
	}
	got, err := registry.PeekRegistrationToken(ctx, plaintext)
	if err != nil {
		t.Fatalf("PeekRegistrationToken: %v", err)
	}
	if got.ID != cluster.ID {
		t.Errorf("peeked cluster = %q, want %q", got.ID, cluster.ID)
	}
}
