package deploymentplan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
)

// VerifiedLinks is deliberately conservative: any absent, stale, or
// inconsistent evidence yields no links. Authorization is checked by the
// caller before this pure URL builder is invoked.
func VerifiedLinks(target resourcetargets.Target, capability *observability.Capability, result *observability.VerificationResult, values map[string]string, now time.Time) ([]Link, error) {
	empty := []Link{}
	if capability == nil || result == nil || result.Result != "passed" || !target.Enabled || !target.Readiness.State.Selectable() {
		return empty, nil
	}
	if result.Target.ID != target.ID || result.Target.Revision != target.Revision || result.Target.ClusterID != target.ResourceRef.ID {
		return empty, nil
	}
	capabilityDigest, err := capability.Digest()
	if err != nil || capabilityDigest != result.CapabilityDigest {
		return empty, nil
	}
	if err := result.ValidateAt(now); err != nil {
		return empty, nil
	}
	if result.Checks.Folder.Name != capability.Folder && !strings.HasSuffix(result.Checks.Folder.Name, "/"+capability.Folder) {
		return empty, nil
	}
	bindings, err := observability.BindLinkVariables(capability.LinkVariables, values)
	if err != nil {
		return empty, err
	}
	var config struct {
		BaseURL string `json:"baseUrl"`
	}
	if err := json.Unmarshal(target.Config, &config); err != nil {
		return empty, fmt.Errorf("grafana target config: %w", err)
	}
	base, err := url.Parse(config.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return empty, fmt.Errorf("grafana target baseUrl is invalid")
	}
	base.Path = strings.TrimRight(base.Path, "/")
	evidence := make(map[string]observability.DashboardCheck, len(result.Checks.Dashboards))
	for _, dashboard := range result.Checks.Dashboards {
		evidence[dashboard.UID] = dashboard
	}
	for _, dashboard := range capability.Dashboards {
		verified, ok := evidence[dashboard.UID]
		if !ok || verified.Title != dashboard.Title {
			return empty, nil
		}
	}
	links := make([]Link, 0, len(capability.Dashboards))
	for _, dashboard := range capability.Dashboards {
		verified := evidence[dashboard.UID]
		link := *base
		link.Path = strings.TrimRight(base.Path, "/") + "/d/" + url.PathEscape(dashboard.UID) + "/" + url.PathEscape(verified.Slug)
		query := url.Values{}
		for _, name := range capability.LinkVariables {
			query.Set("var-"+name, bindings[name])
		}
		link.RawQuery = query.Encode()
		links = append(links, Link{Title: dashboard.Title, UID: dashboard.UID, URL: link.String()})
	}
	return links, nil
}
