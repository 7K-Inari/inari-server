// Package catalog implements the Catalog Service (plan §5.2, §5.5): it
// normalizes discovered capabilities, curated OCI packages, and platform
// apps into one CatalogItem model with versioning, per-tenant/cluster
// visibility policies, and tenant version pins.
package catalog

import (
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
