package gitrepos

import (
	"context"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeTenants resolves org slugs and teams for handler tests.
type fakeTenants struct {
	orgs  map[string]*types.Organization
	teams map[string][]types.Team // orgID → teams
}

func (f *fakeTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if o, ok := f.orgs[slug]; ok {
		return o, nil
	}
	return nil, tenancy.ErrOrgNotFound
}

func (f *fakeTenants) ListTeams(_ context.Context, orgID string) ([]types.Team, error) {
	return f.teams[orgID], nil
}

// permAuthorizer grants relations per user subject.
type permAuthorizer struct {
	allow map[string]map[string]bool // subject → relation → allow
}

func (a *permAuthorizer) Check(_ context.Context, user, relation, _ string) (bool, error) {
	if perms, ok := a.allow[user]; ok {
		return perms[relation], nil
	}
	return false, nil
}

func (a *permAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func TestCallerTeamsResolution(t *testing.T) {
	tenants := &fakeTenants{
		orgs: map[string]*types.Organization{"acme": {ID: "org:1", Slug: "acme"}},
		teams: map[string][]types.Team{"org:1": {
			{ID: "team-a-id", OrgID: "org:1", Name: "team-a", KeycloakGroupPath: "/tenant-acme/team-a"},
			{ID: "team-b-id", OrgID: "org:1", Name: "team-b", KeycloakGroupPath: "/tenant-acme/team-b"},
		}},
	}
	h := NewHandler(nil, tenants, nil)

	id := &authn.Identity{Subject: "u1", Organizations: []string{"acme"},
		Groups: []string{"/tenant-acme/team-a", "/other-org/team-x"}}
	teams, err := h.callerTeams(context.Background(), id, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if len(teams) != 1 || teams[0] != "team-a-id" {
		t.Errorf("teams = %v, want [team-a-id]", teams)
	}
}

func TestListFilterForCaller(t *testing.T) {
	tenants := &fakeTenants{
		orgs: map[string]*types.Organization{"acme": {ID: "org:1", Slug: "acme"}},
		teams: map[string][]types.Team{"org:1": {
			{ID: "team-a-id", OrgID: "org:1", Name: "team-a", KeycloakGroupPath: "/tenant-acme/team-a"},
		}},
	}
	az := &permAuthorizer{allow: map[string]map[string]bool{
		"user:admin": {authz.RelationTenantSettingsWrite: true, authz.RelationTenantRead: true},
		"user:dev":   {authz.RelationTenantRead: true},
	}}
	h := NewHandler(nil, tenants, az)

	// Privileged caller (tenant_settings_write) → nil filter (sees all).
	admin := &authn.Identity{Subject: "admin", Organizations: []string{"acme"}}
	filter, err := h.listFilterForCaller(context.Background(), admin, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if filter != nil {
		t.Errorf("admin filter = %v, want nil", filter)
	}

	// Regular member → own teams.
	dev := &authn.Identity{Subject: "dev", Organizations: []string{"acme"}, Groups: []string{"/tenant-acme/team-a"}}
	filter, err = h.listFilterForCaller(context.Background(), dev, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if len(filter) != 1 || filter[0] != "team-a-id" {
		t.Errorf("dev filter = %v, want [team-a-id]", filter)
	}
}

func TestCanSeeRepo(t *testing.T) {
	h := NewHandler(nil, nil, nil)
	platform := &types.TenantGitRepo{Scope: types.GitRepoScopePlatform}
	teamRepo := &types.TenantGitRepo{Scope: types.GitRepoScopeTeam, TeamID: "team-a-id"}

	if !h.canSeeRepo(platform, nil, false) {
		t.Error("platform repo must be read-visible to every org member")
	}
	if !h.canSeeRepo(teamRepo, []string{"team-a-id"}, false) {
		t.Error("owning team must see its repo")
	}
	if h.canSeeRepo(teamRepo, []string{"team-b-id"}, false) {
		t.Error("foreign team must not see the repo")
	}
	if !h.canSeeRepo(teamRepo, nil, true) {
		t.Error("privileged caller sees everything")
	}
}

func TestCanWriteRepo(t *testing.T) {
	h := NewHandler(nil, nil, nil)
	platform := &types.TenantGitRepo{Scope: types.GitRepoScopePlatform}
	teamRepo := &types.TenantGitRepo{Scope: types.GitRepoScopeTeam, TeamID: "team-a-id"}

	// Platform repos: settings-write only.
	if h.canWriteRepo(platform, nil, false, false) {
		t.Error("platform repo write without settings-write must fail")
	}
	if !h.canWriteRepo(platform, nil, true, false) {
		t.Error("platform repo write with settings-write must pass")
	}
	// Team repos: owning-team member with deployments_create, or settings-write.
	if !h.canWriteRepo(teamRepo, []string{"team-a-id"}, false, true) {
		t.Error("owning team deployer must write")
	}
	if h.canWriteRepo(teamRepo, []string{"team-a-id"}, false, false) {
		t.Error("owning team without deployments_create must not write")
	}
	if h.canWriteRepo(teamRepo, []string{"team-b-id"}, false, true) {
		t.Error("foreign team must not write")
	}
	if !h.canWriteRepo(teamRepo, nil, true, false) {
		t.Error("settings-write must write team repos")
	}
}
