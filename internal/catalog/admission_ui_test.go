package catalog

import (
	"testing"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
)

func TestRequiresUICompatibility(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry trustedsource.IndexEntry
		want  bool
	}{
		{"non UI", trustedsource.IndexEntry{Lanes: []trustedsource.Lane{{Name: "test-packages"}}}, false},
		{"UI lane", trustedsource.IndexEntry{Lanes: []trustedsource.Lane{{Name: "ui"}}}, true},
		{"browser lane", trustedsource.IndexEntry{Lanes: []trustedsource.Lane{{Name: "browser"}}}, true},
		{"compatibility metadata", trustedsource.IndexEntry{Compatibility: &trustedsource.Compatibility{}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := requiresUICompatibility(tc.entry); got != tc.want {
				t.Fatalf("requiresUICompatibility = %v, want %v", got, tc.want)
			}
		})
	}
}
