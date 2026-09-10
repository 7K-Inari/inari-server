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

func TestEffectiveVisibilityMerge(t *testing.T) {
	items := []types.CatalogItem{
		{ID: "public", Name: "public"},
		{ID: "platform-hidden", Name: "platform-hidden"},
		{ID: "org-hidden", Name: "org-hidden"},
		{ID: "both-hidden", Name: "both-hidden"},
	}
	platform := map[string][]types.VisibilityRule{
		"platform-hidden": {{ItemID: "platform-hidden", OrgID: "org-other", ClusterID: "*"}},
		"both-hidden":     {{ItemID: "both-hidden", OrgID: "org-other", ClusterID: "*"}},
	}
	overlay := map[string]bool{
		"org-hidden":  false,
		"both-hidden": false,
	}
	got := effectiveVisibility(items, platform, overlay, "org-1")
	if len(got) != 4 {
		t.Fatalf("got %d entries, want 4", len(got))
	}
	byID := map[string]OrgVisibilityEntry{}
	for _, e := range got {
		byID[e.ItemID] = e
	}
	if e := byID["public"]; !e.Visible || e.OrgHidden || e.PlatformHidden {
		t.Errorf("public = %+v, want visible", e)
	}
	if e := byID["platform-hidden"]; e.Visible || e.OrgHidden || !e.PlatformHidden {
		t.Errorf("platform-hidden = %+v, want hidden by platform only", e)
	}
	if e := byID["org-hidden"]; e.Visible || !e.OrgHidden || e.PlatformHidden {
		t.Errorf("org-hidden = %+v, want hidden by org only", e)
	}
	if e := byID["both-hidden"]; e.Visible || !e.OrgHidden || !e.PlatformHidden {
		t.Errorf("both-hidden = %+v, want hidden by both", e)
	}
}

func TestEffectiveVisibilityOrgCannotUnhidePlatform(t *testing.T) {
	items := []types.CatalogItem{{ID: "i1", Name: "i1"}}
	platform := map[string][]types.VisibilityRule{
		"i1": {{ItemID: "i1", OrgID: "org-other", ClusterID: "*"}},
	}
	overlay := map[string]bool{"i1": true}
	got := effectiveVisibility(items, platform, overlay, "org-1")
	if got[0].Visible {
		t.Error("org overlay must not un-hide a platform-hidden item")
	}
	if got[0].OrgHidden {
		t.Error("explicitly shown by org should not report OrgHidden")
	}
}

func TestEffectiveVisibilityNoOverlayRowDefaultsShown(t *testing.T) {
	items := []types.CatalogItem{{ID: "i1", Name: "i1"}}
	got := effectiveVisibility(items, nil, nil, "org-1")
	if !got[0].Visible || got[0].OrgHidden {
		t.Errorf("no rules and no overlay = %+v, want visible", got[0])
	}
}
