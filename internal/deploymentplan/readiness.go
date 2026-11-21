package deploymentplan

import (
	"errors"
	"fmt"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
)

type ruleEvidenceKey struct {
	file       string
	evaluation observability.Evaluation
}

// validateReadyEvidence binds passing target-side evidence to the exact
// provider-normalized selection and signed assets. It is used at ingest and
// again at read time so previously persisted or superseded evidence fails
// closed after target, policy, or ownership changes.
func validateReadyEvidence(plan *Plan, companion *Companion, target *resourcetargets.Target, result *observability.VerificationResult) error {
	if plan == nil || companion == nil || target == nil || result == nil || plan.Capability == nil || result.Result != "passed" {
		return errors.New("verification_stale: passing evidence requires a plan, companion, target, and capability")
	}
	if target.ID != companion.TargetID || target.Revision != companion.TargetRevision || target.ResourceRef.ID != companion.TargetClusterID {
		return errors.New("verification_stale: target snapshot changed")
	}
	intent, err := BuildPackRenderIntent(plan.Capability, companion.TargetSelection, plan.OrgSlug, plan.Deployment.OwnerTeam)
	if err != nil {
		return fmt.Errorf("verification_stale: invalid approved selection: %w", err)
	}
	folder, _ := intent.PackSpec["folder"].(string)
	datasource, _ := intent.PackSpec["datasource"].(string)
	if result.Checks.Folder.Name != folder {
		return errors.New("verification_stale: folder evidence does not match the approved selection")
	}
	dashboards := make(map[string]observability.DashboardCheck, len(result.Checks.Dashboards))
	for _, check := range result.Checks.Dashboards {
		if _, exists := dashboards[check.UID]; exists {
			return errors.New("verification_stale: duplicate dashboard evidence")
		}
		dashboards[check.UID] = check
	}
	if len(dashboards) != len(plan.Capability.Dashboards) {
		return errors.New("verification_stale: incomplete or unexpected dashboard evidence")
	}
	for _, declared := range plan.Capability.Dashboards {
		check, ok := dashboards[declared.UID]
		if !ok || check.Title != declared.Title {
			return errors.New("verification_stale: dashboard evidence does not match signed metadata")
		}
	}

	if len(result.Checks.Datasources) != 1 || len(plan.Capability.Datasources) != 1 {
		return errors.New("verification_stale: exactly one selected datasource mapping is required")
	}
	logical := ""
	for name := range plan.Capability.Datasources {
		logical = name
	}
	check := result.Checks.Datasources[0]
	if check.Name != datasource || check.Logical != logical {
		return errors.New("verification_stale: datasource evidence does not match the approved mapping")
	}
	config, err := targetConfig(*target)
	if err != nil || config.Evaluation != intent.Evaluation {
		return errors.New("verification_stale: target evaluation or configuration is unavailable")
	}
	datasourceType := ""
	for _, candidate := range config.Datasources {
		if candidate.Name != datasource {
			continue
		}
		if datasourceType != "" {
			return errors.New("verification_stale: ambiguous datasource configuration")
		}
		datasourceType = candidate.Type
	}
	if datasourceType == "" || check.Type != datasourceType {
		return errors.New("verification_stale: datasource type does not match the approved target")
	}

	expectedRules := map[ruleEvidenceKey]int{}
	for _, declared := range plan.Capability.Rules {
		if declared.Evaluation == intent.Evaluation {
			expectedRules[ruleEvidenceKey{file: declared.File, evaluation: declared.Evaluation}]++
		}
	}
	actualRules := map[ruleEvidenceKey]int{}
	for _, check := range result.Checks.Rules {
		actualRules[ruleEvidenceKey{file: check.File, evaluation: check.Evaluation}]++
	}
	if len(actualRules) != len(expectedRules) {
		return errors.New("verification_stale: incomplete or unexpected rule evidence")
	}
	for key, count := range expectedRules {
		if actualRules[key] != count {
			return errors.New("verification_stale: rule evidence does not match the selected evaluation")
		}
	}
	return nil
}
