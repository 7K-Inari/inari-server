package tenantzonefactory

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/7K-Inari/inari-server/internal/cloudaccounts"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

type qaTenantCreator struct{ calls int }

func (f *qaTenantCreator) CreateTenant(_ context.Context, _, slug, _ string) (*types.Organization, []types.Team, error) {
	f.calls++
	return &types.Organization{ID: "org-" + slug, KeycloakOrgID: "kc-" + slug}, nil, nil
}

type qaAccounts struct{ failFirst bool }

func (f *qaAccounts) Register(_ context.Context, _, _ string, _ cloudaccounts.RegisterInput) (*types.CloudAccount, error) {
	if f.failFirst {
		f.failFirst = false
		return &types.CloudAccount{ID: "acct-1"}, nil
	}
	return nil, cloudaccounts.ErrAlreadyRegistered
}

func (f *qaAccounts) Deregister(_ context.Context, _, _, _ string) error { return nil }

type qaClusters struct{ failFirst bool }

func (f *qaClusters) CreateCluster(_ context.Context, _, _, _ string, _ map[string]string) (*types.Cluster, error) {
	if f.failFirst {
		f.failFirst = false
		return nil, errors.New("boom")
	}
	return nil, clusterregistry.ErrClusterNameTaken
}

func (f *qaClusters) IssueToken(_ context.Context, _, _ string) (string, *types.RegistrationToken, error) {
	return "tok", &types.RegistrationToken{}, nil
}

type qaGit struct{ *gitprovider.Fake }

func newQAGit() qaGit { return qaGit{gitprovider.NewFake()} }

// QA: a zone that fails between CloudAccount registration and Cluster
// creation must be resumable; WireZone currently errors with
// "duplicate registration" instead of reusing the existing records.
func TestQAWireZoneResumeAfterPartialFailure(t *testing.T) {
	w := &ModuleWiring{
		Tenants:  &qaTenantCreator{},
		Clusters: &qaClusters{failFirst: true},
		Accounts: &qaAccounts{failFirst: true},
		Git:      newQAGit(),
	}
	zone := &types.TenantZone{Slug: "acme", DisplayName: "Acme", Region: "eu-west-1", Tier: "starter"}
	if _, err := w.WireZone(context.Background(), zone, "arn:role"); err == nil {
		t.Fatal("first run should fail (cluster create boom)")
	}
	if _, err := w.WireZone(context.Background(), zone, "arn:role"); err != nil {
		t.Fatalf("retry after partial failure must resume, got: %v", err)
	}
}

// QA: two concurrent runners on the same zone must not double-vend an AWS
// account (§10 zombie-zone mitigation). There is no idempotency key on
// CreateAccount, so this documents the missing concurrency control.
func TestQAConcurrentRunnersDoubleVend(t *testing.T) {
	aws := NewFakeOrganizations()
	env := &Env{AWS: aws, Bootstrap: NewFakeTrustBootstrap(), Prov: NewFakeProvisioner(),
		Wiring: &qaWiring{}, Config: Config{AccountQuota: 10, MaxAttempts: 5}}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			zone := &types.TenantZone{ID: "z1", Slug: "acme", OUID: "ou-1", Region: "eu-west-1", Tier: "starter"}
			rc := &RunContext{Zone: zone, Steps: map[string]*types.TenantZoneStep{}}
			_, _ = RunSteps(context.Background(), env, ProvisionOrder[:2], provisionSteps, rc,
				func(context.Context, *RunContext, *types.TenantZoneStep) error { return nil })
		}()
	}
	wg.Wait()
	if n := len(aws.CreatedAccounts()); n > 1 {
		t.Fatalf("concurrent runners vended %d accounts for one zone (zombie account)", n)
	}
}

type qaWiring struct{}

func (qaWiring) WireZone(_ context.Context, _ *types.TenantZone, _ string) (*WiringResult, error) {
	return &WiringResult{}, nil
}
func (qaWiring) UnwireZone(_ context.Context, _ *types.TenantZone) error { return nil }

// QA: pure status polls must not consume the per-step attempt budget,
// otherwise a long async step (EKS ~30min) burns MaxAttempts and the first
// genuine error jumps straight to manual_intervention (service.go:253).
func TestQAPollsConsumeAttemptBudget(t *testing.T) {
	aws := NewFakeOrganizations()
	aws.SucceedAfterPolls = 10
	env := &Env{AWS: aws, Config: Config{AccountQuota: 10, MaxAttempts: 3}}
	zone := &types.TenantZone{ID: "z1", Slug: "acme", OUID: "ou-1", Region: "eu-west-1", Tier: "starter"}
	rc := &RunContext{Zone: zone, Steps: map[string]*types.TenantZoneStep{}}
	noop := func(context.Context, *RunContext, *types.TenantZoneStep) error { return nil }
	var lastErr error
	for i := 0; i < 12; i++ {
		_, lastErr = RunSteps(context.Background(), env, ProvisionOrder[1:2], provisionSteps, rc, noop)
		if lastErr != nil {
			break
		}
	}
	st := rc.Steps[types.ZoneStepAccountVend]
	if lastErr != nil {
		t.Fatalf("async polling errored: %v", lastErr)
	}
	if st.Attempts > 2 {
		t.Fatalf("pure polling inflated Attempts to %d (first real failure would exceed MaxAttempts=%d)", st.Attempts, env.Config.MaxAttempts)
	}
}

// QA: the fake Organizations backend accepts CloseAccount polling through
// DescribeCreateAccountStatus with a fresh car-N id, but the real AWS impl
// (aws_aws.go) returns "close-<accountID>" which DescribeCreateAccountStatus
// rejects — fake and real contracts diverge and the decommission path is
// only proven against the fake. This test pins the fake behaviour so any
// fix aligning the two must update both sides.
func TestQAFakeCloseAccountContract(t *testing.T) {
	aws := NewFakeOrganizations()
	res, err := aws.CloseAccount(context.Background(), "100000000001")
	if err != nil {
		t.Fatal(err)
	}
	st, err := aws.DescribeCreateAccountStatus(context.Background(), res.RequestID)
	if err != nil || st.State != "SUCCEEDED" {
		t.Fatalf("fake close polling broken: %v %v", st, err)
	}
}

func TestQAPreflightBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		in      PreflightInput
		denials int
	}{
		{"empty everything", PreflightInput{}, 2},
		{"32-char slug ok", PreflightInput{Slug: "a2345678901234567890123456789012", OUID: "ou-1"}, 0},
		{"slug trailing dash", PreflightInput{Slug: "acme-", OUID: "ou-1"}, 1},
		{"slug uppercase", PreflightInput{Slug: "Acme", OUID: "ou-1"}, 1},
		{"quota zero unlimited", PreflightInput{Slug: "acme", OUID: "ou-1", AccountQuota: 0, AccountCount: 9999}, 0},
		{"quota exhausted", PreflightInput{Slug: "acme", OUID: "ou-1", AccountQuota: 5, AccountCount: 5}, 1},
		{"whitespace-only required tag", PreflightInput{Slug: "acme", OUID: "ou-1", RequiredTags: []string{"cost"}, Tags: map[string]string{"cost": "  "}}, 1},
		{"case-insensitive slug clash", PreflightInput{Slug: "ACME", OUID: "ou-1", ExistingSlugs: []string{"acme"}}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(Preflight(tc.in)); got != tc.denials {
				t.Fatalf("got %d denials %v, want %d", got, Preflight(tc.in), tc.denials)
			}
		})
	}
}
