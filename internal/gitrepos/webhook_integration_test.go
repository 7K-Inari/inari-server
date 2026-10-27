//go:build integration

package gitrepos_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/gitrepos"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

// slowProvisioner tracks concurrent entry (the race the advisory lock
// must prevent), simulates a slow provider call, and persists like the
// real gitwebhook.Provisioner (via the TX it is handed).
type slowProvisioner struct {
	current atomic.Int32
	maxSeen atomic.Int32
}

func (p *slowProvisioner) Provision(ctx context.Context, q db.Querier, _ gitprovider.Provider, repo *types.TenantGitRepo) (string, error) {
	cur := p.current.Add(1)
	for {
		m := p.maxSeen.Load()
		if cur <= m || p.maxSeen.CompareAndSwap(m, cur) {
			break
		}
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(50 * time.Millisecond):
	}
	p.current.Add(-1)
	url := "https://inari.example.com/api/v1/webhooks/git/github"
	if err := inventory.NewStore().SetGitRepoWebhook(ctx, q, repo.ID, []byte("enc"), []byte("dek"), "hook-1", url); err != nil {
		return "", err
	}
	repo.WebhookURL = url
	repo.WebhookExternalID = "hook-1"
	return url, nil
}

// Concurrent (re)provisions of the SAME repo must be serialized by the
// per-repo advisory lock — otherwise the provider hook and the vault can
// end up holding different secrets (interleaved patch/put) and every
// delivery 401s until re-rotation.
func TestEnsureWebhookConcurrentSerialized(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1')`); err != nil {
		t.Fatal(err)
	}
	store := inventory.NewStore()
	row := &types.TenantGitRepo{
		OrgID: "org:1", Name: "baseline", Repo: "acme/state",
		Provider: types.GitRepoProviderGitHub, Scope: types.GitRepoScopePlatform, IsDefault: true,
	}
	if err := store.UpsertGitRepo(ctx, database.Pool, row); err != nil {
		t.Fatal(err)
	}
	prov := &slowProvisioner{}
	svc := gitrepos.NewService(store,
		gitprovider.NewRepoResolver(nil, nil, gitprovider.StaticResolver{P: gitprovider.NewFake()}),
		nil, nil, database).WithWebhookProvisioner(prov)

	const n = 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = svc.EnsureWebhook(ctx, "org:1", row.ID, "user:u1")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("call %d: %v", i, err)
		}
	}
	if got := prov.maxSeen.Load(); got != 1 {
		t.Errorf("max concurrent provisions = %d, want 1 (advisory lock must serialize)", got)
	}
	got, err := store.GetGitRepo(ctx, database.Pool, "org:1", row.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.WebhookURL == "" {
		t.Error("repo must be provisioned after concurrent rotations")
	}
}
