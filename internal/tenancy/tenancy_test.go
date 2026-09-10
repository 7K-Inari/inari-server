package tenancy

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestGroupPath(t *testing.T) {
	got := GroupPath("acme", "platform-team")
	if got != "tenant-acme/platform-team" {
		t.Errorf("GroupPath = %q, want tenant-acme/platform-team", got)
	}
}

func TestDefaultTeams(t *testing.T) {
	if len(DefaultTeams) != 3 {
		t.Fatalf("DefaultTeams = %d, want 3", len(DefaultTeams))
	}
	for _, dt := range DefaultTeams {
		if !dt.Role.Valid() {
			t.Errorf("invalid role %q", dt.Role)
		}
	}
}

func TestAnchorTeamForRole(t *testing.T) {
	want := map[types.Role]string{
		types.RoleOrgAdmin:         "org-admins",
		types.RolePlatformEngineer: "platform-team",
		types.RoleDeveloper:        "developers",
		types.RoleViewer:           "viewers",
	}
	for role, team := range want {
		got, ok := AnchorTeamForRole(role)
		if !ok || got != team {
			t.Errorf("AnchorTeamForRole(%q) = %q, %v; want %q", role, got, ok, team)
		}
	}
	if _, ok := AnchorTeamForRole(types.Role("bogus")); ok {
		t.Error("AnchorTeamForRole(bogus) ok = true, want false")
	}
	// Every anchor team granting a default role must be a default team,
	// except org-admins which is materialized lazily.
	for role, dt := range map[types.Role]string{
		types.RolePlatformEngineer: "platform-team",
		types.RoleDeveloper:        "developers",
		types.RoleViewer:           "viewers",
	} {
		found := false
		for _, d := range DefaultTeams {
			if d.Name == dt && d.Role == role {
				found = true
			}
		}
		if !found {
			t.Errorf("anchor team %q for %q not among DefaultTeams", dt, role)
		}
	}
}
