package verification_test

import (
	"strings"
	"testing"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	verification "github.com/7K-Inari/inari-server/internal/verification"
)

const (
	digestA = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digestC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func validPolicy() *verification.Policy {
	p := verification.DefaultPolicy("inst-1")
	p.OrgID = "org-1"
	p.InstanceUID = "2b6e4424-87a4-4f7c-b6d8-dfe2f6a894f8"
	p.Revision = 1
	p.Binding = verification.PolicyBinding{
		AppItemID: "hiroba/example", AppVersion: "1.4.0", AppArtifactDigest: digestA,
		SpecDigest: digestB, SuiteGrantID: "vsg-1", SuiteDigest: digestC,
		Profile: verification.ProfileStage, ParameterContract: "inari.smoke.params.v1",
	}
	return p
}

func validEnvironment(environment trustedsource.Environment) *verification.EnvironmentPolicy {
	profiles := []string{"stage"}
	if environment == trustedsource.EnvironmentProduction {
		profiles = []string{"prod"}
	}
	return &verification.EnvironmentPolicy{
		ID: "vep-1", OrgID: "org-1", TargetID: "rt-1", TargetRevision: 1,
		Environment: environment, Revision: 1, MaxTimeout: "15m", MaxActive: 2, MaxPending: 2,
		MinWorkflowTTLSeconds: 60, MaxWorkflowTTLSeconds: 3600, MaxResultDays: 30,
		AllowedProfiles:       profiles,
		AllowedTriggers:       []string{"onRevisionChange", "onSync", "manual", "cron"},
		AllowedFailureActions: []string{"notify", "pausePromotion", "blockPromotion"},
	}
}

func validGrant() *verification.SuiteGrant {
	return &verification.SuiteGrant{
		SuiteReleaseID: "vsr-1", SuiteDigest: digestC, Profile: verification.ProfileStage,
		Revision: 1, ParameterContract: "inari.smoke.params.v1", SideEffect: verification.SideEffectReadOnly,
		ServiceAccountName: "verify-stage", ServiceAccountNamespace: "inari-verification",
		RBACPolicyDigest: digestB, EgressPolicyRef: "verification-readonly",
		AllowedRBAC: []verification.RBACRule{{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"get", "list"}}},
		MaxTimeout:  "10m", MaxActive: 1, MaxPending: 1, MaxResultBytes: 65536,
	}
}

func TestDefaultPolicyUsesSecureDefaults(t *testing.T) {
	p := verification.DefaultPolicy("inst-1")
	if !p.Enabled || !p.Triggers.OnRevisionChange.Enabled || !p.Triggers.Manual.Enabled {
		t.Fatalf("default triggers are not enabled: %#v", p.Triggers)
	}
	if p.Triggers.OnSync.Enabled || p.Triggers.Cron.Enabled {
		t.Fatalf("optional triggers must default off: %#v", p.Triggers)
	}
	if p.Concurrency.MaxActive != 1 || p.Concurrency.MaxPending != 1 || p.Concurrency.QueuedRevisionPolicy != "latestOnly" {
		t.Fatalf("unsafe concurrency defaults: %#v", p.Concurrency)
	}
	if p.AddonAbsent != verification.AddonAbsentBlock || p.FailureAction != verification.FailurePausePromotion {
		t.Fatalf("unsafe failure defaults: %q %q", p.AddonAbsent, p.FailureAction)
	}
}

func TestPolicyValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*verification.Policy)
		want   string
	}{
		{name: "valid"},
		{name: "app digest", mutate: func(p *verification.Policy) { p.Binding.AppArtifactDigest = "latest" }, want: "appArtifactDigest"},
		{name: "suite digest", mutate: func(p *verification.Policy) { p.Binding.SuiteDigest = "tag" }, want: "suiteDigest"},
		{name: "replace concurrency", mutate: func(p *verification.Policy) { p.Concurrency.QueuedRevisionPolicy = "replace" }, want: "queuedRevisionPolicy"},
		{name: "zero active", mutate: func(p *verification.Policy) { p.Concurrency.MaxActive = 0 }, want: "maxActive"},
		{name: "rollback failure action", mutate: func(p *verification.Policy) { p.FailureAction = "rollback" }, want: "failureAction"},
		{name: "cron schedule required", mutate: func(p *verification.Policy) {
			p.Triggers.Cron.Enabled = true
			p.Triggers.Cron.ScheduleSetID = "nightly"
			p.Triggers.Cron.Timezone = "UTC"
		}, want: "schedules"},
		{name: "unknown notification event", mutate: func(p *verification.Policy) { p.Notifications.Events = []string{"rolledBack"} }, want: "events"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPolicy()
			if tt.mutate != nil {
				tt.mutate(p)
			}
			err := p.Validate()
			if tt.want == "" && err != nil {
				t.Fatalf("valid policy rejected: %v", err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestGrantProductionGuardrails(t *testing.T) {
	production := validEnvironment(trustedsource.EnvironmentProduction)
	base := validGrant()
	base.Profile = verification.ProfileProd
	if err := base.ValidateGrant(production); err != nil {
		t.Fatalf("valid read-only production grant rejected: %v", err)
	}
	tests := []struct {
		name        string
		mutate      func(*verification.SuiteGrant)
		environment *verification.EnvironmentPolicy
		want        string
	}{
		{name: "suite RBAC wildcard", mutate: func(g *verification.SuiteGrant) { g.AllowedRBAC[0].Verbs = []string{"*"} }, want: "wildcard"},
		{name: "suite created RBAC", mutate: func(g *verification.SuiteGrant) { g.AllowedRBAC[0].Resources = []string{"rolebindings"} }, want: "RBAC administration"},
		{name: "synthetic needs fixtures and approval", mutate: func(g *verification.SuiteGrant) { g.SideEffect = verification.SideEffectSyntheticWrite }, environment: production, want: "isolated fixture"},
		{name: "mutating needs change window", mutate: func(g *verification.SuiteGrant) {
			g.SideEffect = verification.SideEffectMutating
			g.FixtureNamespace = "verify-fixtures"
			g.CleanupRequired = true
			g.RequirePerRunApproval = true
			g.ApproverTeamIDs = []string{"security"}
		}, environment: production, want: "changeWindow"},
		{name: "legacy exception denied in production", mutate: func(g *verification.SuiteGrant) { g.LegacyNonProductionException = true }, environment: production, want: "non-production"},
		{name: "arbitrary public logs URL", mutate: func(g *verification.SuiteGrant) { g.ArgoUIBaseURL = "http://argo.example" }, want: "https"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := validGrant()
			g.Profile = verification.ProfileProd
			tt.mutate(g)
			env := tt.environment
			if env == nil {
				env = production
			}
			err := g.ValidateGrant(env)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}
