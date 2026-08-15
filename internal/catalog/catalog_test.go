package catalog

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.2.0", "1.10.0", -1},
		{"v1.2.0", "1.2.0", 0},
		{"2.0.0-rc.1", "2.0.0", -1},
		{"0.9", "0.9.1", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestLatestVersionPrefersHighestSemver(t *testing.T) {
	versions := []types.CatalogItemVersion{
		{Version: "1.0.0", Channel: "stable"},
		{Version: "1.2.0", Channel: "stable"},
		{Version: "1.10.0", Channel: "stable"},
		{Version: "2.0.0-rc.1", Channel: "incubating"},
	}
	got := latestInChannel(versions, "stable")
	if got != "1.10.0" {
		t.Errorf("latestInChannel stable = %q, want 1.10.0", got)
	}
	got = latestInChannel(versions, "incubating")
	if got != "2.0.0-rc.1" {
		t.Errorf("latestInChannel incubating = %q, want 2.0.0-rc.1", got)
	}
}

func TestVisibleRulesEmptyMeansPublic(t *testing.T) {
	if !visibleTo(nil, "org-1", "cluster-1") {
		t.Error("no rules should mean visible to everyone")
	}
}

func TestVisibleRulesMatch(t *testing.T) {
	rules := []types.VisibilityRule{
		{ItemID: "i1", OrgID: "org-1", ClusterID: "*"},
		{ItemID: "i1", OrgID: "org-2", ClusterID: "cluster-9"},
	}
	if !visibleTo(rules, "org-1", "anything") {
		t.Error("org-1 wildcard cluster should be visible")
	}
	if visibleTo(rules, "org-2", "cluster-1") {
		t.Error("org-2 only visible on cluster-9")
	}
	if !visibleTo(rules, "org-2", "cluster-9") {
		t.Error("org-2 on cluster-9 should be visible")
	}
	if visibleTo(rules, "org-3", "cluster-9") {
		t.Error("org-3 should not be visible")
	}
}

func TestDiscoveredProjectionSkipsMetadata(t *testing.T) {
	caps := []types.Capability{
		{Kind: types.CapabilityKindCRD, Name: "postgreses.db.example.com", Group: "db.example.com", Version: "v1"},
		{Kind: types.CapabilityKindClusterMetadata, Name: "cluster"},
		{Kind: types.CapabilityKindKRORGD, Name: "webapp", Group: "kro.run", Version: "v1alpha1"},
	}
	items := projectDiscovered("cluster-1", caps)
	if len(items) != 2 {
		t.Fatalf("projected %d items, want 2", len(items))
	}
	if items[0].Source != types.CatalogSourceDiscovered {
		t.Errorf("source = %q, want discovered", items[0].Source)
	}
}
