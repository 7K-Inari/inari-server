package authn

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestCallerTeamIDs(t *testing.T) {
	teams := []types.Team{
		{ID: "t1", KeycloakGroupPath: "/tenant-acme/team-a"},
		{ID: "t2", KeycloakGroupPath: "/tenant-acme/team-b"},
		{ID: "t3", KeycloakGroupPath: "/tenant-other/team-c"},
	}
	cases := []struct {
		name string
		id   *Identity
		want []string
	}{
		{"nil identity", nil, nil},
		{"no groups", &Identity{Subject: "u1"}, nil},
		{"one match", &Identity{Groups: []string{"/tenant-acme/team-a"}}, []string{"t1"}},
		{"many matches", &Identity{Groups: []string{"/tenant-acme/team-b", "/tenant-acme/team-a"}}, []string{"t1", "t2"}},
		{"no match", &Identity{Groups: []string{"/tenant-acme/unknown"}}, nil},
		{"exact path only", &Identity{Groups: []string{"tenant-acme/team-a"}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CallerTeamIDs(tc.id, teams)
			if len(got) != len(tc.want) {
				t.Fatalf("CallerTeamIDs = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("CallerTeamIDs = %v, want %v", got, tc.want)
				}
			}
		})
	}
}
