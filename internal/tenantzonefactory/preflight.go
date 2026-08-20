// Request pre-flight for tenant zone vending (plan §5.12 step 1, §10):
// naming rules, OU quota, region allow-list, and mandatory cost-tag
// guardrails. Denials return reasons, not just a boolean (§5.11
// request-time policy feedback).
package tenantzonefactory

import (
	"fmt"
	"regexp"
	"strings"
)

var slugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)

// PreflightInput carries everything the pre-flight checks need; callers
// gather quota/account counts from the AWSOrganizations seam so the checks
// themselves stay pure.
type PreflightInput struct {
	Slug           string
	Region         string
	Tier           string
	OUID           string
	ExistingSlugs  []string
	AccountCount   int // current accounts under the target OU
	AccountQuota   int // configured max accounts for the OU
	AllowedRegions []string
	AllowedTiers   []string
	RequiredTags   []string // mandatory cost/allocation tag keys
	Tags           map[string]string
}

// Preflight runs all request pre-flight checks and returns the list of
// denial reasons (empty = pass).
func Preflight(in PreflightInput) []string {
	var reasons []string
	if !slugRe.MatchString(in.Slug) {
		reasons = append(reasons, fmt.Sprintf("slug %q must match %s (lowercase alphanumeric + dashes, 3-32 chars)", in.Slug, slugRe))
	}
	for _, s := range in.ExistingSlugs {
		if strings.EqualFold(s, in.Slug) {
			reasons = append(reasons, fmt.Sprintf("slug %q is already in use", in.Slug))
			break
		}
	}
	if in.OUID == "" {
		reasons = append(reasons, "target organizational unit (ouId) is required")
	}
	if in.AccountQuota > 0 && in.AccountCount >= in.AccountQuota {
		reasons = append(reasons, fmt.Sprintf("OU account quota exhausted: %d/%d accounts in use (§10 quota pre-check)", in.AccountCount, in.AccountQuota))
	}
	if len(in.AllowedRegions) > 0 && !contains(in.AllowedRegions, in.Region) {
		reasons = append(reasons, fmt.Sprintf("region %q is not in the allow-list %v", in.Region, in.AllowedRegions))
	}
	if len(in.AllowedTiers) > 0 && !contains(in.AllowedTiers, in.Tier) {
		reasons = append(reasons, fmt.Sprintf("tier %q is not in the allow-list %v", in.Tier, in.AllowedTiers))
	}
	for _, key := range in.RequiredTags {
		if strings.TrimSpace(in.Tags[key]) == "" {
			reasons = append(reasons, fmt.Sprintf("mandatory cost tag %q is missing (budget guardrail)", key))
		}
	}
	return reasons
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
