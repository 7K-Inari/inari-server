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
