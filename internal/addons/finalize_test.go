package addons

import (
	"context"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// PR-merge finalization: the deferred registration is enqueued with the
// manifest as committed at the merge SHA, the merge SHA becomes the
// addon's commit, and pr_url is cleared (idempotent redelivery).
func TestFinalizePRMerge(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	cat := newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod", nil)}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	repo := seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyPullRequest)
	svc := newTestService(store, cat, clusters, git, queue)

	mergeSHA := "deadbeeffeed"
	// The merged manifest (as it exists at the merge SHA — possibly edited
	// in the PR after Inari opened it).
	if _, err := git.CommitFiles(ctx, repo.Repo, mergeSHA, []gitprovider.File{
		{Path: "addons/cert-manager/application.yaml", Content: []byte("kind: Application\n# edited in review\n")},
	}, "merge"); err != nil {
		t.Fatal(err)
	}
	row := &types.ClusterAddon{
		ID: "addon-1", OrgID: "org:1", ClusterID: "c1", CatalogItem: "platform:cert-manager",
		State: types.AddonStateManaged, DeployMode: types.AddonDeployModeApplication,
		RepoID: repo.ID, RepoPath: "addons/cert-manager", ChartVersion: "v1.16.1",
		ArgoCDApp: "inari-addon-addon-1", CommitSHA: "old-sha",
		PRURL: "https://github.com/acme/state/pull/9",
	}
	if err := store.UpsertClusterAddon(ctx, nil, row); err != nil {
		t.Fatal(err)
	}

	found, err := svc.FinalizePRMerge(ctx, "org:1", row.PRURL, mergeSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("found = false, want true")
	}
	if len(queue.cmds) != 1 {
		t.Fatalf("registration commands = %d, want 1", len(queue.cmds))
	}
	if !strings.Contains(string(queue.cmds[0].Payload), "edited in review") {
		t.Errorf("registration must carry the merged manifest: %s", queue.cmds[0].Payload)
	}
	got, err := store.GetClusterAddonByID(ctx, nil, "org:1", "addon-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitSHA != mergeSHA || got.PRURL != "" {
		t.Errorf("row = commit %q pr %q, want %q and empty", got.CommitSHA, got.PRURL, mergeSHA)
	}

	// Redelivery: pr_url is cleared, so nothing matches and nothing
	// re-enqueues (idempotent).
	found, err = svc.FinalizePRMerge(ctx, "org:1", "https://github.com/acme/state/pull/9", mergeSHA)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("redelivery must not match")
	}
	if len(queue.cmds) != 1 {
		t.Errorf("redelivery re-enqueued: %d commands", len(queue.cmds))
	}
}

// An unknown PR URL matches nothing (found=false, no side effects).
func TestFinalizePRMergeUnknownPR(t *testing.T) {
	store := newFakeStore()
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyPullRequest)
	svc := newTestService(store, newFakeCatalog(), &fakeClusters{}, git, queue)
	found, err := svc.FinalizePRMerge(context.Background(), "org:1", "https://github.com/acme/state/pull/99", "sha")
	if err != nil {
		t.Fatal(err)
	}
	if found || len(queue.cmds) != 0 {
		t.Errorf("found=%v cmds=%d, want false/0", found, len(queue.cmds))
	}
}
