package planlimits

import (
	"context"
	"fmt"
	"net/http"
)

const (
	LimitClusters       = "clusters"
	LimitDeveloperSeats = "developer-seats"

	GateApprovals      = "approvals"
	GatePolicyPacks    = "policy-packs"
	GateNotifications  = "notifications"
	GateIdPBrokering   = "idp-brokering"
	GateFleetRollouts  = "fleet-rollouts"
	GateDriftDetection = "drift-detection"
	GateZoneVending    = "zone-vending"
)

// Evaluator resolves one tenant's generic limits for enforcement.
type Evaluator interface {
	Evaluate(ctx context.Context, tenantID string) (Evaluation, error)
}

// ProviderEvaluator evaluates limits from a PlanLimitsProvider.
type ProviderEvaluator struct {
	provider   PlanLimitsProvider
	upgradeURL string
}

// NewEvaluator returns an evaluator with the supplied outbound upgrade URL.
// A nil provider preserves the unlimited OSS default.
func NewEvaluator(provider PlanLimitsProvider, upgradeURL string) *ProviderEvaluator {
	if provider == nil {
		provider = UnlimitedProvider{}
	}
	return &ProviderEvaluator{provider: provider, upgradeURL: upgradeURL}
}

func (e *ProviderEvaluator) Evaluate(ctx context.Context, tenantID string) (Evaluation, error) {
	limits, err := e.provider.PlanLimits(ctx, tenantID)
	if err != nil {
		return Evaluation{}, &LimitsUnavailableError{
			Status: http.StatusServiceUnavailable,
			Title:  http.StatusText(http.StatusServiceUnavailable),
			Detail: "plan limits are temporarily unavailable",
			Code:   "plan_limits_unavailable",
			cause:  err,
		}
	}
	return Evaluation{limits: cloneLimits(limits), upgradeURL: e.upgradeURL}, nil
}

// Evaluation is an immutable view of one tenant's limits.
type Evaluation struct {
	limits     Limits
	upgradeURL string
}

func (e Evaluation) Limits() Limits { return cloneLimits(e.limits) }

func (e Evaluation) MaxClusters() *int64 { return cloneInt64(e.limits.MaxClusters) }

func (e Evaluation) MaxDeveloperSeats() *int64 { return cloneInt64(e.limits.MaxDeveloperSeats) }

// CheckQuota denies a new unit when currentUsage has reached the configured
// cap. Existing usage above a reduced cap remains readable/removable, but any
// additional unit is denied.
func (e Evaluation) CheckQuota(limit string, currentUsage int64) error {
	if currentUsage < 0 {
		return fmt.Errorf("planlimits: negative usage for %s", limit)
	}
	var maximum *int64
	switch limit {
	case LimitClusters:
		maximum = e.limits.MaxClusters
	case LimitDeveloperSeats:
		maximum = e.limits.MaxDeveloperSeats
	default:
		return fmt.Errorf("planlimits: unknown quota %q", limit)
	}
	if maximum == nil || currentUsage < *maximum {
		return nil
	}
	current, allowed, requested := currentUsage, *maximum, int64(1)
	return &LimitExceededError{
		Type:         "about:blank",
		Title:        http.StatusText(http.StatusTooManyRequests),
		Status:       http.StatusTooManyRequests,
		Detail:       fmt.Sprintf("%s limit exceeded: %d of %d already used", limit, currentUsage, *maximum),
		Code:         "plan_limit_exceeded",
		LimitKind:    "quota",
		Limit:        limit,
		CurrentUsage: &current,
		MaxAllowed:   &allowed,
		Requested:    &requested,
		UpgradeURL:   e.upgradeURL,
	}
}

func (e Evaluation) FeatureEnabled(gate string) bool {
	return e.limits.AllFeatures || e.limits.FeatureGates[gate]
}

func (e Evaluation) CheckFeature(gate string) error {
	if e.FeatureEnabled(gate) {
		return nil
	}
	return &LimitExceededError{
		Type:       "about:blank",
		Title:      http.StatusText(http.StatusForbidden),
		Status:     http.StatusForbidden,
		Detail:     fmt.Sprintf("feature %q is not enabled for this tenant", gate),
		Code:       "plan_limit_exceeded",
		LimitKind:  "feature",
		Limit:      gate,
		UpgradeURL: e.upgradeURL,
	}
}

func cloneLimits(in Limits) Limits {
	out := in
	out.MaxClusters = cloneInt64(in.MaxClusters)
	out.MaxDeveloperSeats = cloneInt64(in.MaxDeveloperSeats)
	if in.FeatureGates != nil {
		out.FeatureGates = make(map[string]bool, len(in.FeatureGates))
		for name, enabled := range in.FeatureGates {
			out.FeatureGates[name] = enabled
		}
	}
	return out
}

func cloneInt64(in *int64) *int64 {
	if in == nil {
		return nil
	}
	value := *in
	return &value
}
