// Package catalog implements the Catalog Service (plan §5.2, §5.5): it
// normalizes discovered capabilities, curated OCI packages, and platform
// apps into one CatalogItem model with versioning, per-tenant/cluster
// visibility policies, and tenant version pins.
package catalog

import (
	"sort"
	"strconv"
	"strings"

	"github.com/7K-Inari/inari-server/internal/types"
)

// compareVersions compares dotted numeric versions with optional v-prefix
// and pre-release suffix. Returns -1, 0, 1.
func compareVersions(a, b string) int {
	pa, preA := splitVersion(a)
	pb, preB := splitVersion(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	// Equal numeric parts: a pre-release is older than the release.
	if preA == preB {
		return 0
	}
	if preA == "" {
		return 1
	}
	if preB == "" {
		return -1
	}
	return strings.Compare(preA, preB)
}

func splitVersion(v string) ([]int, string) {
	v = strings.TrimPrefix(v, "v")
	var pre string
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			nums = append(nums, 0)
			continue
		}
		nums = append(nums, n)
	}
	return nums, pre
}

// latestInChannel returns the highest version in a channel ("" = any).
func latestInChannel(versions []types.CatalogItemVersion, channel string) string {
	best := ""
	for _, v := range versions {
		if channel != "" && v.Channel != channel {
			continue
		}
		if best == "" || compareVersions(v.Version, best) > 0 {
			best = v.Version
		}
	}
	return best
}

// visibleTo evaluates visibility rules: an item with no rules is public;
// otherwise at least one rule must match org ('*' wildcard) and cluster
// ('*' wildcard).
func visibleTo(rules []types.VisibilityRule, orgID, clusterID string) bool {
	if len(rules) == 0 {
		return true
	}
	for _, r := range rules {
		orgOK := r.OrgID == "*" || r.OrgID == orgID
		clusterOK := r.ClusterID == "*" || r.ClusterID == "" || r.ClusterID == clusterID
		if orgOK && clusterOK {
			return true
		}
	}
	return false
}

// OrgVisibilityEntry is one catalog item's effective visibility for a tenant
// org: platform rule AND org overlay (Settings design §3.4).
type OrgVisibilityEntry struct {
	ItemID         string `json:"itemId"`
	Name           string `json:"name"`
	DisplayName    string `json:"displayName"`
	Visible        bool   `json:"visible"`
	OrgHidden      bool   `json:"orgHidden"`
	PlatformHidden bool   `json:"platformHidden"`
}

// effectiveVisibility merges platform visibility rules with the org overlay
// (item_id → visible). An org can hide items the platform exposes, but can
// never un-hide an item the platform hides.
func effectiveVisibility(items []types.CatalogItem, platform map[string][]types.VisibilityRule, overlay map[string]bool, orgID string) []OrgVisibilityEntry {
	out := make([]OrgVisibilityEntry, 0, len(items))
	for _, it := range items {
		platformOK := visibleTo(platform[it.ID], orgID, "*")
		orgOK := true
		if v, ok := overlay[it.ID]; ok {
			orgOK = v
		}
		out = append(out, OrgVisibilityEntry{
			ItemID:         it.ID,
			Name:           it.Name,
			DisplayName:    it.DisplayName,
			Visible:        platformOK && orgOK,
			OrgHidden:      !orgOK,
			PlatformHidden: !platformOK,
		})
	}
	return out
}

// matchesFacet reports whether an item passes the browse facets. Persisted
// items are already filtered in SQL; this runs in Go for discovered
// projections, which have no category (excluded when a category filter is
// active) and no description.
func matchesFacet(it types.CatalogItem, opts types.CatalogListOptions) bool {
	if opts.Source != "" && string(it.Source) != opts.Source {
		return false
	}
	if opts.Category != "" && it.Category != opts.Category {
		return false
	}
	if opts.Query != "" {
		q := strings.ToLower(opts.Query)
		hay := strings.ToLower(it.Name + " " + it.DisplayName + " " + it.Description)
		if !strings.Contains(hay, q) {
			return false
		}
	}
	return true
}

// sortCatalogItems orders the merged (persisted + discovered) result so the
// page slice stays correct across both kinds (ADR-0009). Discovered items
// carry capability FirstSeenAt as createdAt; zero times sort last under
// "newest" and first under "oldest".
func sortCatalogItems(items []types.CatalogItem, sortBy string) {
	lessName := func(a, b types.CatalogItem) bool { return a.Name < b.Name }
	var less func(a, b types.CatalogItem) bool
	switch sortBy {
	case types.CatalogSortNameDesc:
		less = func(a, b types.CatalogItem) bool { return b.Name < a.Name }
	case types.CatalogSortNewest:
		less = func(a, b types.CatalogItem) bool {
			if !a.CreatedAt.Equal(b.CreatedAt) {
				if a.CreatedAt.IsZero() {
					return false
				}
				if b.CreatedAt.IsZero() {
					return true
				}
				return a.CreatedAt.After(b.CreatedAt)
			}
			return lessName(a, b)
		}
	case types.CatalogSortOldest:
		less = func(a, b types.CatalogItem) bool {
			if !a.CreatedAt.Equal(b.CreatedAt) {
				if a.CreatedAt.IsZero() {
					return true
				}
				if b.CreatedAt.IsZero() {
					return false
				}
				return a.CreatedAt.Before(b.CreatedAt)
			}
			return lessName(a, b)
		}
	default:
		less = lessName
	}
	sort.SliceStable(items, func(i, j int) bool { return less(items[i], items[j]) })
}

// pageSlice applies offset/limit pagination to an already-sorted slice.
// Limit 0 means "no limit".
func pageSlice[T any](items []T, limit, offset int) []T {
	if offset >= len(items) {
		return nil
	}
	if offset > 0 {
		items = items[offset:]
	}
	if limit > 0 && limit < len(items) {
		items = items[:limit]
	}
	return items
}

// projectDiscovered turns live cluster capabilities into catalog item views
// (plan §5.5 source 1). cluster-metadata capabilities are operational
// signals, not deployable items.
func projectDiscovered(clusterID string, caps []types.Capability) []types.CatalogItem {
	var out []types.CatalogItem
	for _, c := range caps {
		if c.Kind == types.CapabilityKindClusterMetadata {
			continue
		}
		name := c.Name
		if c.Group != "" && !strings.Contains(name, ".") {
			name = c.Name + "." + c.Group
		}
		out = append(out, types.CatalogItem{
			ID:          "discovered:" + clusterID + ":" + string(c.Kind) + "/" + name,
			Source:      types.CatalogSourceDiscovered,
			Name:        name,
			DisplayName: c.Name,
			CapabilityRef: &types.CapabilityRef{
				Kind:  c.Kind,
				Group: c.Group,
				Name:  c.Name,
			},
			ApprovalPolicy: types.ApprovalPolicyAuto,
			CreatedAt:      c.FirstSeenAt,
		})
	}
	return out
}
