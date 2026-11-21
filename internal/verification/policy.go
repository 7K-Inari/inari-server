package verification

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	contract "github.com/7K-Inari/inari-api/contract/verification/v1"
	"github.com/robfig/cron/v3"
)

var (
	verificationDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	dnsLabelPattern           = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	identifierPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

// DefaultPolicy returns secure team defaults for a new instance policy.
func DefaultPolicy(instanceID string) *Policy {
	return &Policy{
		InstanceID: instanceID,
		Enabled:    true,
		Triggers: Triggers{
			OnRevisionChange: TriggerToggle{Enabled: true},
			OnSync:           SyncTrigger{Enabled: false, Mode: "observedSync"},
			Manual:           TriggerToggle{Enabled: true},
			Cron:             CronConfig{Enabled: false, Timezone: "UTC"},
		},
		Timeout:       "10m",
		Concurrency:   ConcurrencyConfig{MaxActive: 1, MaxPending: 1, QueuedRevisionPolicy: "latestOnly"},
		Retention:     RetentionConfig{WorkflowTTLSeconds: 3600, SuccessfulHistory: 3, FailedHistory: 3, ResultDays: 30},
		Notifications: NotificationConfig{Events: []string{"failed", "blocked"}},
		AddonAbsent:   AddonAbsentBlock,
		FailureAction: FailurePausePromotion,
	}
}

// Validate normalizes and validates a team policy.
func (p *Policy) Validate() error {
	if p == nil {
		return errors.New("policy is required")
	}
	if strings.TrimSpace(p.InstanceID) == "" {
		return errors.New("instanceId is required")
	}
	if p.Revision < 1 {
		return errors.New("policyRevision must be positive")
	}
	if !identifierPattern.MatchString(p.InstanceUID) {
		return errors.New("instanceUid is required")
	}
	b := &p.Binding
	if strings.TrimSpace(b.AppItemID) == "" || strings.TrimSpace(b.AppVersion) == "" {
		return errors.New("appItemId and appVersion are required")
	}
	if !verificationDigestPattern.MatchString(b.AppArtifactDigest) {
		return errors.New("appArtifactDigest must be an immutable sha256 digest")
	}
	if !verificationDigestPattern.MatchString(b.SpecDigest) {
		return errors.New("specDigest must be an immutable sha256 digest")
	}
	if b.DesiredCommit != "" && !regexp.MustCompile(`^[0-9a-fA-F]{40}$`).MatchString(b.DesiredCommit) {
		return errors.New("desiredCommit must be empty or a full Git SHA")
	}
	if strings.TrimSpace(b.SuiteGrantID) == "" || !verificationDigestPattern.MatchString(b.SuiteDigest) {
		return errors.New("suiteGrantId and immutable suiteDigest are required")
	}
	if b.Profile != ProfileCI && b.Profile != ProfileStage && b.Profile != ProfileProd {
		return errors.New("profile must be ci, stage, or prod")
	}
	if strings.TrimSpace(b.ParameterContract) == "" {
		return errors.New("parameterContract is required")
	}
	timeout, err := time.ParseDuration(p.Timeout)
	if err != nil || timeout < time.Second || timeout > time.Hour {
		return errors.New("timeout must be between 1s and 1h")
	}
	if p.Concurrency.MaxActive < 1 || p.Concurrency.MaxActive > 100 {
		return errors.New("concurrency.maxActive must be between 1 and 100")
	}
	if p.Concurrency.MaxPending < 0 || p.Concurrency.MaxPending > 1000 {
		return errors.New("concurrency.maxPending must be between 0 and 1000")
	}
	if p.Concurrency.QueuedRevisionPolicy != "latestOnly" && p.Concurrency.QueuedRevisionPolicy != "all" {
		return errors.New("concurrency.queuedRevisionPolicy must be latestOnly or all; replace is not supported")
	}
	if p.Retention.WorkflowTTLSeconds < 60 || p.Retention.WorkflowTTLSeconds > 7*24*3600 {
		return errors.New("retention.workflowTTLSeconds must be between 60 and 604800")
	}
	if p.Retention.ResultDays < 1 || p.Retention.ResultDays > 365 {
		return errors.New("retention.resultDays must be between 1 and 365")
	}
	if p.Retention.SuccessfulHistory < 0 || p.Retention.FailedHistory < 0 || p.Retention.SuccessfulHistory > 100 || p.Retention.FailedHistory > 100 {
		return errors.New("retention history limits must be between 0 and 100")
	}
	if p.AddonAbsent != AddonAbsentSkip && p.AddonAbsent != AddonAbsentBlock {
		return errors.New("addonAbsent must be skip or block")
	}
	switch p.FailureAction {
	case FailureNotify, FailurePausePromotion, FailureBlockPromotion:
	default:
		return errors.New("failureAction must be notify, pausePromotion, or blockPromotion; rollback is forbidden")
	}
	if p.Triggers.OnSync.Enabled {
		if p.Triggers.OnSync.Mode == "" {
			p.Triggers.OnSync.Mode = "observedSync"
		}
		if p.Triggers.OnSync.Mode != "observedSync" && p.Triggers.OnSync.Mode != "postSync" {
			return errors.New("onSync.mode must be observedSync or postSync")
		}
	}
	if p.Triggers.Cron.Enabled {
		c := &p.Triggers.Cron
		if !identifierPattern.MatchString(c.ScheduleSetID) {
			return errors.New("cron.scheduleSetId is required")
		}
		if c.Timezone == "" {
			c.Timezone = "UTC"
		}
		if _, err := time.LoadLocation(c.Timezone); err != nil {
			return fmt.Errorf("cron.timezone: %w", err)
		}
		if len(c.Schedules) == 0 {
			return errors.New("cron.schedules must contain at least one schedule")
		}
		if len(c.Schedules) > 20 {
			return errors.New("cron.schedules exceeds the 20-schedule limit")
		}
		for _, schedule := range c.Schedules {
			if _, err := cron.ParseStandard(schedule); err != nil {
				return fmt.Errorf("cron.schedules: %w", err)
			}
		}
		if c.StartingDeadlineSeconds < 0 || c.StartingDeadlineSeconds > 86400 {
			return errors.New("cron.startingDeadlineSeconds must be between 0 and 86400")
		}
	}
	seenEndpoints := map[string]bool{}
	for _, endpoint := range p.Notifications.EndpointIDs {
		if strings.TrimSpace(endpoint) == "" || seenEndpoints[endpoint] {
			return errors.New("notifications.endpointIds must be nonempty and unique")
		}
		seenEndpoints[endpoint] = true
	}
	seenEvents := map[string]bool{}
	for _, event := range p.Notifications.Events {
		switch event {
		case "started", "passed", "failed", "blocked":
		default:
			return fmt.Errorf("notifications.events contains unsupported event %q", event)
		}
		if seenEvents[event] {
			return fmt.Errorf("notifications.events contains duplicate %q", event)
		}
		seenEvents[event] = true
	}
	return nil
}

// ValidateGrant checks platform-owned grant fields against its environment.
func (g *SuiteGrant) ValidateGrant(environmentPolicy *EnvironmentPolicy) error {
	if g == nil || environmentPolicy == nil {
		return errors.New("grant and environment policy are required")
	}
	if !verificationDigestPattern.MatchString(g.SuiteDigest) {
		return errors.New("suiteDigest must be an immutable sha256 digest")
	}
	if strings.TrimSpace(g.SuiteReleaseID) == "" || g.Revision < 1 {
		return errors.New("suiteReleaseId and positive grantRevision are required")
	}
	if !contains(environmentPolicy.AllowedProfiles, g.Profile) {
		return fmt.Errorf("profile %q is not allowed by the environment policy", g.Profile)
	}
	switch environmentPolicy.Environment {
	case trustedsource.EnvironmentProduction:
		if g.Profile != ProfileProd {
			return errors.New("production targets require the prod profile")
		}
	case trustedsource.EnvironmentStaging, trustedsource.EnvironmentDevelopment:
		if g.Profile != ProfileStage {
			return errors.New("development and staging targets require the stage profile")
		}
	default:
		return errors.New("environment policy has an unknown environment")
	}
	if g.LegacyNonProductionException && environmentPolicy.Environment != trustedsource.EnvironmentDevelopment {
		return errors.New("legacy eligibility exception is non-production only")
	}
	if g.SideEffect == "" {
		g.SideEffect = SideEffectReadOnly
	}
	if g.SideEffect != SideEffectReadOnly && g.SideEffect != SideEffectSyntheticWrite && g.SideEffect != SideEffectMutating {
		return errors.New("sideEffects must be readOnly, syntheticWrite, or mutating")
	}
	if !dnsLabelPattern.MatchString(g.ServiceAccountName) || g.ServiceAccountName == "default" || !dnsLabelPattern.MatchString(g.ServiceAccountNamespace) {
		return errors.New("a preapproved non-default ServiceAccount name and namespace are required")
	}
	if !dnsLabelPattern.MatchString(g.EgressPolicyRef) {
		return errors.New("egressPolicyRef must name a preapproved policy")
	}
	if !verificationDigestPattern.MatchString(g.RBACPolicyDigest) {
		return errors.New("rbacPolicyDigest must be an immutable sha256 digest")
	}
	for _, rule := range g.AllowedRBAC {
		for _, group := range rule.APIGroups {
			if group == "*" || group == "rbac.authorization.k8s.io" {
				return errors.New("wildcard API groups and RBAC administration are forbidden")
			}
		}
		for _, resource := range rule.Resources {
			if resource == "*" {
				return errors.New("wildcard resources are forbidden")
			}
			switch resource {
			case "roles", "rolebindings", "clusterroles", "clusterrolebindings":
				return errors.New("RBAC administration resources are forbidden")
			}
		}
		for _, verb := range rule.Verbs {
			if verb == "*" || verb == "impersonate" || verb == "bind" || verb == "escalate" {
				return errors.New("wildcard and privilege-escalating verbs are forbidden")
			}
			if g.SideEffect == SideEffectReadOnly && verb != "get" && verb != "list" && verb != "watch" {
				return fmt.Errorf("readOnly grants cannot allow verb %q", verb)
			}
		}
	}
	if environmentPolicy.Environment == trustedsource.EnvironmentProduction && g.SideEffect != SideEffectReadOnly {
		if !dnsLabelPattern.MatchString(g.FixtureNamespace) || !g.CleanupRequired {
			return errors.New("synthetic or mutating production runs require an isolated fixture namespace and cleanup")
		}
		if !g.RequirePerRunApproval || len(g.ApproverTeamIDs) == 0 {
			return errors.New("synthetic or mutating production runs require explicit named-team approval")
		}
		if strings.TrimSpace(g.ChangeWindow) == "" {
			return errors.New("synthetic or mutating production runs require a changeWindow")
		}
	}
	grantTimeout, err := time.ParseDuration(g.MaxTimeout)
	if err != nil || grantTimeout < time.Second {
		return errors.New("maxTimeout must be a positive duration")
	}
	environmentTimeout, err := time.ParseDuration(environmentPolicy.MaxTimeout)
	if err != nil || environmentTimeout < time.Second || grantTimeout > environmentTimeout {
		return errors.New("grant maxTimeout exceeds the environment policy")
	}
	if g.MaxActive < 1 || g.MaxActive > environmentPolicy.MaxActive || g.MaxPending < 0 || g.MaxPending > environmentPolicy.MaxPending {
		return errors.New("grant concurrency exceeds the environment policy")
	}
	if g.MaxResultBytes == 0 {
		g.MaxResultBytes = 65536
	}
	if g.MaxResultBytes < 1 || g.MaxResultBytes > 1<<20 {
		return errors.New("maxResultBytes must be between 1 and 1048576")
	}
	if g.ArgoUIBaseURL != "" {
		u, err := url.Parse(g.ArgoUIBaseURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return errors.New("argoUiBaseUrl must be an https URL without credentials or fragments")
		}
	}
	return nil
}

// ValidateAgainstGrant applies environment and grant limits to a team policy.
func (p *Policy) ValidateAgainstGrant(environment *EnvironmentPolicy, grant *SuiteGrant, now time.Time) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if environment == nil || grant == nil || grant.RevokedAt != nil || (grant.ExpiresAt != nil && !now.Before(*grant.ExpiresAt)) {
		return errors.New("suite_grant_denied: grant is unavailable, expired, or revoked")
	}
	if grant.SuiteDigest != p.Binding.SuiteDigest || grant.Profile != p.Binding.Profile || grant.ID != p.Binding.SuiteGrantID {
		return errors.New("suite_grant_denied: policy does not match the exact digest+profile grant")
	}
	if grant.ParameterContract != p.Binding.ParameterContract {
		return errors.New("suite_grant_denied: parameterContract mismatch")
	}
	timeout, _ := time.ParseDuration(p.Timeout)
	maxTimeout, _ := time.ParseDuration(grant.MaxTimeout)
	if timeout > maxTimeout {
		return errors.New("timeout exceeds the suite grant")
	}
	if p.Concurrency.MaxActive > grant.MaxActive || p.Concurrency.MaxPending > grant.MaxPending {
		return errors.New("concurrency exceeds the suite grant")
	}
	if p.Retention.WorkflowTTLSeconds < environment.MinWorkflowTTLSeconds || p.Retention.WorkflowTTLSeconds > environment.MaxWorkflowTTLSeconds || p.Retention.ResultDays > environment.MaxResultDays {
		return errors.New("retention exceeds the environment policy")
	}
	if p.Binding.Profile == ProfileProd && grant.SideEffect != SideEffectReadOnly {
		if p.Triggers.OnRevisionChange.Enabled || p.Triggers.OnSync.Enabled || p.Triggers.Cron.Enabled || !grant.RequirePerRunApproval {
			return errors.New("side_effect_denied: mutating production profiles allow approved manual runs only")
		}
	}
	if p.Triggers.OnSync.Enabled && p.Triggers.OnSync.Mode == "postSync" && grant.SideEffect != SideEffectReadOnly {
		return errors.New("side_effect_denied: only readOnly profiles may use postSync")
	}
	if !contains(environment.AllowedFailureActions, p.FailureAction) {
		return errors.New("failureAction is denied by the environment policy")
	}
	for _, endpoint := range environment.RequiredNotificationEndpointIDs {
		if !contains(p.Notifications.EndpointIDs, endpoint) {
			return fmt.Errorf("required notification endpoint %q is not selected", endpoint)
		}
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// TriggerAllowed verifies that the environment permits the requested source.
func (p *Policy) TriggerAllowed(environment *EnvironmentPolicy, kind contract.TriggerKind) bool {
	return environment != nil && contains(environment.AllowedTriggers, string(kind))
}
