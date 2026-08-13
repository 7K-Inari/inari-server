package tenancy

import "testing"

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
