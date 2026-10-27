//go:build integration

package inventory

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

// Migration 0038 columns + the webhook-ingress lookup/mutation methods
// against real SQL.
func TestGitRepoWebhookColumns(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	s := NewStore()

	row := &types.TenantGitRepo{
		OrgID: "org:1", Name: "baseline", Repo: "acme/state",
		Provider: types.GitRepoProviderGitHub, Scope: types.GitRepoScopePlatform, IsDefault: true,
	}
	if err := s.UpsertGitRepo(ctx, database.Pool, row); err != nil {
		t.Fatal(err)
	}

	// Unprovisioned: no secret, and the cross-org lookup still resolves.
	if _, _, found, err := s.GitRepoWebhookSecret(ctx, database.Pool, row.ID); err != nil || found {
		t.Errorf("unprovisioned secret = found %v, err %v", found, err)
	}
	got, err := s.FindGitRepoByRepo(ctx, database.Pool, "acme/state", types.GitRepoProviderGitHub)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != row.ID || got.WebhookURL != "" || got.WebhookExternalID != "" {
		t.Errorf("row = %+v", got)
	}

	// Provision: ciphertext round-trips; the hook registration is exposed.
	if err := s.SetGitRepoWebhook(ctx, database.Pool, row.ID, []byte("enc"), []byte("dek"), "hook-7",
		"https://inari.example.com/api/v1/webhooks/git/github"); err != nil {
		t.Fatal(err)
	}
	secretEnc, dekEnc, found, err := s.GitRepoWebhookSecret(ctx, database.Pool, row.ID)
	if err != nil || !found {
		t.Fatalf("secret = found %v, err %v", found, err)
	}
	if string(secretEnc) != "enc" || string(dekEnc) != "dek" {
		t.Error("ciphertext mismatch")
	}
	got, err = s.GetGitRepo(ctx, database.Pool, "org:1", row.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.WebhookURL != "https://inari.example.com/api/v1/webhooks/git/github" || got.WebhookExternalID != "hook-7" {
		t.Errorf("hook fields = %q %q", got.WebhookURL, got.WebhookExternalID)
	}

	// Unknown repo slug → ErrRepoNotFound.
	if _, err := s.FindGitRepoByRepo(ctx, database.Pool, "acme/unknown", types.GitRepoProviderGitHub); err == nil {
		t.Error("want ErrRepoNotFound for unknown slug")
	}

	// The reconcile sweep's source query: provisioned rows drop out,
	// unprovisioned rows (any org) stay listed.
	missing, err := s.ListGitReposWithoutWebhook(ctx, database.Pool)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range missing {
		if r.ID == row.ID {
			t.Error("provisioned repo must not be listed as missing a webhook")
		}
	}
	seedOrg(t, database, ctx, "org:2", "other")
	bare := &types.TenantGitRepo{
		OrgID: "org:2", Name: "baseline", Repo: "other/state",
		Provider: types.GitRepoProviderGitHub, Scope: types.GitRepoScopePlatform, IsDefault: true,
	}
	if err := s.UpsertGitRepo(ctx, database.Pool, bare); err != nil {
		t.Fatal(err)
	}
	missing, err = s.ListGitReposWithoutWebhook(ctx, database.Pool)
	if err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, r := range missing {
		if r.ID == bare.ID {
			listed = true
		}
	}
	if !listed {
		t.Error("unprovisioned repo must be listed for the reconcile sweep")
	}
}

// FindByPRURL + MarkPRMerged for instances and addons against real SQL
// (the pr_url guard is what makes webhook redelivery idempotent).
func TestPRMergeLookupAndMark(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	clusterID := seedCluster(t, database, ctx, "org:1", "c1")
	s := NewStore()

	inst := &types.ResourceInstance{
		ID: "inst-1", OrgID: "org:1", ClusterID: clusterID, CatalogItemID: "item", Version: "v1",
		Spec: []byte(`{}`), Health: "unknown", State: types.InstanceStateDeploying,
		ManagementMode: types.ManagementModeAdopt,
		CommitSHA:      "old", PRURL: "https://github.com/acme/state/pull/3", Generation: 1,
	}
	if err := s.Create(ctx, database.Pool, inst); err != nil {
		t.Fatal(err)
	}

	got, err := s.FindInstanceByPRURL(ctx, database.Pool, "org:1", inst.PRURL)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "inst-1" {
		t.Errorf("instance = %+v", got)
	}
	applied, err := s.MarkInstancePRMerged(ctx, database.Pool, "org:1", "inst-1", "merge-sha")
	if err != nil || !applied {
		t.Fatalf("mark = %v, %v", applied, err)
	}
	got, _ = s.Get(ctx, database.Pool, "inst-1")
	if got.CommitSHA != "merge-sha" || got.PRURL != "" {
		t.Errorf("after merge: %+v", got)
	}
	// Redelivery: the pr_url guard makes the second mark a no-op.
	applied, err = s.MarkInstancePRMerged(ctx, database.Pool, "org:1", "inst-1", "merge-sha")
	if err != nil || applied {
		t.Errorf("redelivery mark = %v, %v, want false nil", applied, err)
	}
	if _, err := s.FindInstanceByPRURL(ctx, database.Pool, "org:1", inst.PRURL); err == nil {
		t.Error("cleared pr_url must not match")
	}

	// Addon twin.
	addon := &types.ClusterAddon{
		ID: "addon-1", OrgID: "org:1", ClusterID: clusterID, CatalogItem: "platform:cert-manager",
		State: types.AddonStateManaged, CommitSHA: "old", PRURL: "https://github.com/acme/state/pull/4",
	}
	if err := s.UpsertClusterAddon(ctx, database.Pool, addon); err != nil {
		t.Fatal(err)
	}
	a, err := s.FindAddonByPRURL(ctx, database.Pool, "org:1", addon.PRURL)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "addon-1" {
		t.Errorf("addon = %+v", a)
	}
	applied, err = s.MarkAddonPRMerged(ctx, database.Pool, "org:1", "addon-1", "merge-sha-2")
	if err != nil || !applied {
		t.Fatalf("addon mark = %v, %v", applied, err)
	}
	applied, err = s.MarkAddonPRMerged(ctx, database.Pool, "org:1", "addon-1", "merge-sha-2")
	if err != nil || applied {
		t.Errorf("addon redelivery mark = %v, %v, want false nil", applied, err)
	}
}
