package tenantzonefactory

import (
	"context"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/clusterregistry"
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
		Manifest:           clusterregistry.ManifestParams{AgentImageRepo: "img", AgentImageTag: "v1", GatewayAddress: "https://gw"},
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
	if !strings.Contains(files["tenants/acme/dns-record.yaml"], "mode: shared-record") {
		t.Errorf("dns-record manifest = %s", files["tenants/acme/dns-record.yaml"])
	}

	// Retry (resume after partial run) re-ensures without error.
	if _, err := w.WireZone(context.Background(), zone, "arn:role"); err != nil {
		t.Fatalf("WireZone retry: %v", err)
	}
}

func TestWireZoneWithoutPlatformResources(t *testing.T) {
	git := gitprovider.NewFake()
	w := &ModuleWiring{
		Tenants:  &qaTenantCreator{},
		Clusters: &qaClusters{},
		Accounts: &qaAccounts{},
		Git:      git,
		Manifest: clusterregistry.ManifestParams{AgentImageRepo: "img", AgentImageTag: "v1", GatewayAddress: "https://gw"},
	}
	zone := &types.TenantZone{Slug: "acme", DisplayName: "Acme", Region: "eu-west-1", Tier: "starter"}
	if _, err := w.WireZone(context.Background(), zone, "arn:role"); err != nil {
		t.Fatalf("WireZone: %v", err)
	}
	if files := git.Files("inari-platform-gitops", "main"); len(files) != 0 {
		t.Errorf("platform gitops repo touched without configuration: %v", files)
	}
}
