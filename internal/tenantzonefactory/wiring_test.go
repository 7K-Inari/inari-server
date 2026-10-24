package tenantzonefactory

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

type fakePlatformEnsurer struct{ orgs []string }

func (f *fakePlatformEnsurer) EnsureBaseResources(_ context.Context, org *types.Organization) error {
	f.orgs = append(f.orgs, org.ID)
	return nil
}

func TestWireZoneEnsuresPlatformResourcesAndCommitsManifests(t *testing.T) {
	git := gitprovider.NewFake()
	ensurer := &fakePlatformEnsurer{}
	w := &ModuleWiring{
		Tenants:            &qaTenantCreator{},
		Clusters:           &qaClusters{},
		Accounts:           &qaAccounts{},
		Git:                git,
		PlatformResources:  ensurer,
		PlatformGitOpsRepo: "inari-platform-gitops",
		Agent:              AgentInstallParams{ImageRepo: "img", GatewayAddress: "https://gw"},
	}
	zone := &types.TenantZone{Slug: "acme", DisplayName: "Acme", Region: "eu-west-1", Tier: "starter"}
	if _, err := w.WireZone(context.Background(), zone, "arn:role"); err != nil {
		t.Fatalf("WireZone: %v", err)
	}
	if len(ensurer.orgs) != 1 || ensurer.orgs[0] != "org-acme" {
		t.Errorf("EnsureBaseResources calls = %v, want [org-acme]", ensurer.orgs)
	}
	files := git.Files("inari-platform-gitops", "main")
	for _, want := range []string{
		"tenants/acme/keycloak-realm.yaml",
		"tenants/acme/dns-record.yaml",
		"tenants/acme/tenant-namespace.yaml",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("platform gitops repo missing %s (has %v)", want, files)
		}
	}
	if !strings.Contains(files["tenants/acme/dns-record.yaml"], "zoneRef: shared") {
		t.Errorf("dns-record manifest = %s", files["tenants/acme/dns-record.yaml"])
	}

	// Retry (resume after partial run) re-ensures without error.
	if _, err := w.WireZone(context.Background(), zone, "arn:role"); err != nil {
		t.Fatalf("WireZone retry: %v", err)
	}
}

// fakeBaselineRepos records EnsureDefaultBaselineRepo/BindClusterBaseline
// calls.
type fakeBaselineRepos struct {
	calls     []string
	bindCalls []string
	err       error
	bindErr   error
}

func (f *fakeBaselineRepos) EnsureDefaultBaselineRepo(_ context.Context, orgID, repo string) error {
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, orgID+"|"+repo)
	return nil
}

func (f *fakeBaselineRepos) BindClusterBaseline(_ context.Context, clusterID string) error {
	if f.bindErr != nil {
		return f.bindErr
	}
	f.bindCalls = append(f.bindCalls, clusterID)
	return nil
}

// TestWireZoneRegistersBaselineRepo pins the Feature A registry write: the
// zone's state repo is upserted as the org's default platform repo.
func TestWireZoneRegistersBaselineRepo(t *testing.T) {
	git := gitprovider.NewFake()
	repos := &fakeBaselineRepos{}
	w := &ModuleWiring{
		Tenants:       &qaTenantCreator{},
		Clusters:      &qaClusters{},
		Accounts:      &qaAccounts{},
		Git:           git,
		BaselineRepos: repos,
		Agent:         AgentInstallParams{ImageRepo: "img", GatewayAddress: "https://gw"},
	}
	zone := &types.TenantZone{Slug: "acme", DisplayName: "Acme", Region: "eu-west-1", Tier: "starter"}
	if _, err := w.WireZone(context.Background(), zone, "arn:role"); err != nil {
		t.Fatalf("WireZone: %v", err)
	}
	if len(repos.calls) != 1 || repos.calls[0] != "org-acme|acme-inari-state" {
		t.Errorf("EnsureDefaultBaselineRepo calls = %v, want [org-acme|acme-inari-state]", repos.calls)
	}
	// The zone's cluster is bound to the default row (it was created before
	// the row existed, so the registration-time default could not apply).
	if len(repos.bindCalls) != 1 {
		t.Errorf("BindClusterBaseline calls = %v, want 1 call", repos.bindCalls)
	}
	// Idempotent on retry.
	if _, err := w.WireZone(context.Background(), zone, "arn:role"); err != nil {
		t.Fatalf("WireZone retry: %v", err)
	}
}

// TestWireZoneBaselineRepoFailurePropagates pins the retry contract: a
// registry write failure surfaces so the step retries.
func TestWireZoneBaselineRepoFailurePropagates(t *testing.T) {
	git := gitprovider.NewFake()
	w := &ModuleWiring{
		Tenants:       &qaTenantCreator{},
		Clusters:      &qaClusters{},
		Accounts:      &qaAccounts{},
		Git:           git,
		BaselineRepos: &fakeBaselineRepos{err: errors.New("boom")},
		Agent:         AgentInstallParams{ImageRepo: "img", GatewayAddress: "https://gw"},
	}
	zone := &types.TenantZone{Slug: "acme", DisplayName: "Acme", Region: "eu-west-1", Tier: "starter"}
	if err := func() error {
		_, err := w.WireZone(context.Background(), zone, "arn:role")
		return err
	}(); err == nil || !strings.Contains(err.Error(), "baseline repo") {
		t.Fatalf("WireZone err = %v, want baseline repo failure", err)
	}
}

func TestWireZoneWithoutPlatformResources(t *testing.T) {
	git := gitprovider.NewFake()
	w := &ModuleWiring{
		Tenants:  &qaTenantCreator{},
		Clusters: &qaClusters{},
		Accounts: &qaAccounts{},
		Git:      git,
		Agent:    AgentInstallParams{ImageRepo: "img", GatewayAddress: "https://gw"},
	}
	zone := &types.TenantZone{Slug: "acme", DisplayName: "Acme", Region: "eu-west-1", Tier: "starter"}
	if _, err := w.WireZone(context.Background(), zone, "arn:role"); err != nil {
		t.Fatalf("WireZone: %v", err)
	}
	if files := git.Files("inari-platform-gitops", "main"); len(files) != 0 {
		t.Errorf("platform gitops repo touched without configuration: %v", files)
	}
}
