package tenancy

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/types"
)

func TestGroupPath(t *testing.T) {
	got := GroupPath("acme", "platform-team")
	if got != "tenant-acme/platform-team" {
		t.Errorf("GroupPath = %q, want tenant-acme/platform-team", got)
	}
}

func TestDefaultTeams(t *testing.T) {
	if len(DefaultTeams) != 4 {
		t.Fatalf("DefaultTeams = %d, want 4", len(DefaultTeams))
	}
	var haveOrgAdmins bool
	for _, dt := range DefaultTeams {
		if authz.BuiltinRolePermissions(dt.RoleName) == nil {
			t.Errorf("default team %q bound to unknown built-in role %q", dt.Name, dt.RoleName)
		}
		if dt.Name == OrgAdminsTeamName {
			haveOrgAdmins = true
			if dt.RoleName != authz.BuiltinRoleAdmin {
				t.Errorf("org-admins team grants %q, want admin", dt.RoleName)
			}
		}
	}
	if !haveOrgAdmins {
		t.Error("DefaultTeams must include the org-admins anchor team (tenant bootstrap)")
	}
}

func TestAnchorTeamForRole(t *testing.T) {
	want := map[string]string{
		authz.BuiltinRoleAdmin:    "org-admins",
		authz.BuiltinRoleOperator: "platform-team",
		authz.BuiltinRoleEditor:   "developers",
		authz.BuiltinRoleViewer:   "viewers",
	}
	for roleName, team := range want {
		got := AnchorTeamForRole(&types.Role{Name: roleName, Builtin: true})
		if got != team {
			t.Errorf("AnchorTeamForRole(%q) = %q, want %q", roleName, got, team)
		}
	}
	// A custom role's anchor is a team named after it.
	if got := AnchorTeamForRole(&types.Role{Name: "deployer"}); got != "deployer" {
		t.Errorf("AnchorTeamForRole(custom) = %q, want deployer", got)
	}
	// Every built-in anchor team must be a default team bound to the same
	// role (org-admins is created with every tenant, ADR-0013).
	for roleName, dt := range want {
		found := false
		for _, d := range DefaultTeams {
			if d.Name == dt && d.RoleName == roleName {
				found = true
			}
		}
		if !found {
			t.Errorf("anchor team %q for %q not among DefaultTeams", dt, roleName)
		}
	}
}
