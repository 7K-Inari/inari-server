// Platform-declared agent compatibility: the inari-platform chart declares
// agent.supportedRange (semver range) and agent.recommended (exact version);
// inari-server receives them via INARI_AGENT_SUPPORTED_RANGE /
// INARI_AGENT_RECOMMENDED_VERSION. When the range is set it replaces the
// legacy hardcoded N/N-1 skew policy (SupportedAgentVersion in channels.go);
// when unset the legacy policy applies unchanged.
package fleetmanager

import (
	"fmt"

	"github.com/blang/semver"
)

// SupportedAgentVersionInRange reports whether the reported agent version
// falls inside the platform-declared semver range (e.g. ">=0.5.0 <0.6.0").
// An error is returned for an unparseable range or version.
func SupportedAgentVersionInRange(rangeExpr, reported string) (bool, error) {
	rng, err := semver.ParseRange(rangeExpr)
	if err != nil {
		return false, fmt.Errorf("parse supported range %q: %w", rangeExpr, err)
	}
	v, err := semver.ParseTolerant(reported)
	if err != nil {
		return false, fmt.Errorf("parse reported version %q: %w", reported, err)
	}
	return rng(v), nil
}

// AgentSupported reports whether the control plane serves the reported agent
// version. Precedence: the platform-declared range wins when set; otherwise
// the legacy N/N-1 policy against the current version applies. Both empty
// disables the check (admit). An unparseable range fails closed: the
// operator misconfiguration must not silently admit arbitrary agents.
func AgentSupported(supportedRange, current, reported string) bool {
	if supportedRange != "" {
		ok, err := SupportedAgentVersionInRange(supportedRange, reported)
		return err == nil && ok
	}
	if current == "" {
		return true
	}
	return SupportedAgentVersion(current, reported)
}

// UpgradeAvailable reports whether the reported agent version is behind the
// platform-recommended version. False when no recommendation is configured,
// the agent never reported a version, either version is unparseable, or the
// agent already runs the recommendation (or newer).
func UpgradeAvailable(recommended, reported string) bool {
	if recommended == "" || reported == "" {
		return false
	}
	rec, err := semver.ParseTolerant(recommended)
	if err != nil {
		return false
	}
	rep, err := semver.ParseTolerant(reported)
	if err != nil {
		return false
	}
	return rep.LT(rec)
}
