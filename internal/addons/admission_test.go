package addons

import (
	"context"
	"errors"
	"testing"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

type denyAddonCatalog struct{ *fakeCatalog }

func (d denyAddonCatalog) AdmitVersion(context.Context, string, string, trustedsource.Environment) (*catalog.AdmittedVersion, error) {
	return nil, &artifactadmission.Error{Code: artifactadmission.CodeSignatureInvalid, Err: errors.New("bad signature")}
}

type recordingAddonCatalog struct {
	*fakeCatalog
	environments []trustedsource.Environment
	err          error
}

func (c *recordingAddonCatalog) AdmitVersion(_ context.Context, itemID, version string, environment trustedsource.Environment) (*catalog.AdmittedVersion, error) {
	c.environments = append(c.environments, environment)
	if c.err != nil {
		return nil, c.err
	}
	for i := range c.versions[itemID] {
		if c.versions[itemID][i].Version == version {
			return &catalog.AdmittedVersion{Version: &c.versions[itemID][i]}, nil
		}
	}
	return nil, catalog.ErrVersionNotFound
}

func externalFleetFixture(cat CatalogResolver) (*fakeStore, *fakeClusters, *gitprovider.Fake, *Service) {
	store := newFakeStore()
	clusters := &fakeClusters{clusters: []types.Cluster{
		activeCluster("c-dev", "org:1", "dev", map[string]string{"inari.dev/environment": "development"}),
		activeCluster("c-prod", "org:1", "prod", map[string]string{"inari.dev/environment": "production"}),
	}}
	git := gitprovider.NewFake()
	baseline := seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
	store.addons[addonKey("*", "core/cert-manager")] = &types.ClusterAddon{
		ID: "addon-fleet", OrgID: "org:1", ClusterID: "*", CatalogItem: "core/cert-manager", State: types.AddonStateManaged,
		DeployMode: types.AddonDeployModeApplicationSet, RepoID: baseline.ID, RepoPath: "addons/core/cert-manager",
		ChartVersion: "v1.16.1", Namespace: "cert-manager",
		Source: types.SourceDescriptor{Kind: types.SourceKindHelm, Helm: &types.HelmSource{RepoURL: "https://charts.jetstack.io", Chart: "cert-manager", Version: "v1.16.1"}},
	}
	resolver := gitprovider.NewRepoResolver(fakeRepoStoreAdapter{store}, nil, gitprovider.StaticResolver{P: git})
	return store, clusters, git, NewService(nil, store, cat, clusters, resolver, &fakeQueue{}, nil)
}

func externalFleetCatalog() *fakeCatalog {
	cat := newFakeCatalog()
	item := cat.items["platform:cert-manager"]
	item.ID = "core/cert-manager"
	item.SourceID = "core"
	cat.items[item.ID] = item
	cat.versions[item.ID] = cat.versions["platform:cert-manager"]
	return cat
}

func TestFleetRerenderUsesProductionPolicyForMixedTargets(t *testing.T) {
	cat := &recordingAddonCatalog{fakeCatalog: externalFleetCatalog()}
	_, _, git, service := externalFleetFixture(cat)
	row := service.store.(*fakeStore).addons[addonKey("*", "core/cert-manager")]
	if err := service.rerenderFleetAddon(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	if len(cat.environments) != 1 || cat.environments[0] != trustedsource.EnvironmentProduction {
		t.Fatalf("fleet admission environments = %v, want production for mixed targets", cat.environments)
	}
	if len(git.Files("acme/state", "main")) == 0 {
		t.Fatal("admitted fleet re-render produced no manifest")
	}
}

func TestFleetRerenderAdmissionDenialHasNoSideEffects(t *testing.T) {
	cat := &recordingAddonCatalog{fakeCatalog: externalFleetCatalog(), err: &artifactadmission.Error{Code: artifactadmission.CodeSignatureInvalid, Err: errors.New("bad signature")}}
	_, _, git, service := externalFleetFixture(cat)
	row := service.store.(*fakeStore).addons[addonKey("*", "core/cert-manager")]
	if err := service.rerenderFleetAddon(context.Background(), row); !artifactadmission.IsCode(err, artifactadmission.CodeSignatureInvalid) {
		t.Fatalf("error = %v, want signature_invalid", err)
	}
	if len(git.Files("acme/state", "main")) != 0 {
		t.Fatal("denied fleet re-render wrote files")
	}
}

func TestFleetRerenderRejectsEmptyFleet(t *testing.T) {
	cat := &recordingAddonCatalog{fakeCatalog: externalFleetCatalog()}
	store, clusters, git, service := externalFleetFixture(cat)
	clusters.clusters = nil
	row := store.addons[addonKey("*", "core/cert-manager")]
	if err := service.rerenderFleetAddon(context.Background(), row); !errors.Is(err, ErrEmptyFleet) {
		t.Fatalf("error = %v, want ErrEmptyFleet", err)
	}
	if len(cat.environments) != 0 || len(git.Files("acme/state", "main")) != 0 {
		t.Fatalf("empty fleet performed admission/render side effects: environments=%v files=%d", cat.environments, len(git.Files("acme/state", "main")))
	}
}

func TestAdoptAdmissionDenialHasNoSideEffects(t *testing.T) {
	cat := newFakeCatalog()
	item := cat.items["platform:cert-manager"]
	item.ID = "core/cert-manager"
	item.SourceID = "core"
	cat.items[item.ID] = item
	cat.versions[item.ID] = cat.versions["platform:cert-manager"]
	store := newFakeStore()
	clusters := &fakeClusters{clusters: []types.Cluster{{ID: "c1", OrgID: "org:1", State: types.ClusterStateActive}}}
	git := gitprovider.NewFake()
	seedBaselineRepo(store, git, "org:1", "acme/acme-inari-state", types.CommitPolicyDirect)
	resolver := gitprovider.NewRepoResolver(fakeRepoStoreAdapter{store}, nil, gitprovider.StaticResolver{P: git})
	queue := &fakeQueue{}
	service := NewService(nil, store, denyAddonCatalog{cat}, clusters, resolver, queue, nil)
	_, err := service.Adopt(context.Background(), "org:1", "c1", item.ID, AdoptInput{Version: "v1.16.2"}, "user:test")
	if !artifactadmission.IsCode(err, artifactadmission.CodeSignatureInvalid) {
		t.Fatalf("error = %v, want signature_invalid", err)
	}
	if len(git.Files("acme/acme-inari-state", "main")) != 0 || len(store.addons) != 0 || len(queue.cmds) != 0 {
		t.Fatalf("denied adopt produced side effects: files=%d rows=%d commands=%d", len(git.Files("acme/acme-inari-state", "main")), len(store.addons), len(queue.cmds))
	}
}
