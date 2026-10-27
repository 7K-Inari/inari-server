package gitrepos

import (
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeProvisioner records Provision calls.
type fakeProvisioner struct {
	calls []string // repo row IDs
	err   error
}

func (f *fakeProvisioner) Provision(_ context.Context, _ db.Querier, _ gitprovider.Provider, repo *types.TenantGitRepo) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.calls = append(f.calls, repo.ID)
	repo.WebhookURL = "https://inari.example.com/api/v1/webhooks/git/github"
	repo.WebhookExternalID = "hook-1"
	return repo.WebhookURL, nil
}

func registerPlatformRepo(t *testing.T, svc *Service) *types.TenantGitRepo {
	t.Helper()
	row, err := svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "baseline", Repo: "acme/state", Scope: types.GitRepoScopePlatform, IsDefault: true,
	}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// Registration provisions the webhook when a provisioner is wired.
func TestRegisterProvisionsWebhook(t *testing.T) {
	prov := &fakeProvisioner{}
	svc := NewService(newFakeStore(), repoResolver(&fakeResolver{provider: gitprovider.NewFake()}), nil, nil).
		WithWebhookProvisioner(prov)
	row := registerPlatformRepo(t, svc)
	if len(prov.calls) != 1 || prov.calls[0] != row.ID {
		t.Errorf("provision calls = %v, want [%s]", prov.calls, row.ID)
	}
	if row.WebhookURL == "" {
		t.Error("row must carry the hook URL after provisioning")
	}
}

// Provisioning failure is non-fatal at registration (the explicit endpoint
// retries); the repo is still registered.
func TestRegisterWebhookFailureNonFatal(t *testing.T) {
	prov := &fakeProvisioner{err: errors.New("provider down")}
	svc := NewService(newFakeStore(), repoResolver(&fakeResolver{provider: gitprovider.NewFake()}), nil, nil).
		WithWebhookProvisioner(prov)
	row := registerPlatformRepo(t, svc)
	if row.ID == "" {
		t.Error("repo must be registered despite provisioning failure")
	}
}

// No provisioner wired: registration skips provisioning entirely.
func TestRegisterNoProvisioner(t *testing.T) {
	svc := NewService(newFakeStore(), repoResolver(&fakeResolver{provider: gitprovider.NewFake()}), nil, nil)
	row := registerPlatformRepo(t, svc)
	if row.WebhookURL != "" {
		t.Error("no provisioner must leave the hook URL empty")
	}
}

// The reconcile sweeper provisions repos created outside Register (TZF
// baseline, legacy git-config mirror) or whose registration-time provision
// failed; already-provisioned repos are skipped; per-repo failures don't
// abort the sweep.
func TestReconcileWebhooks(t *testing.T) {
	store := newFakeStore()
	prov := &fakeProvisioner{}
	svc := NewService(store, repoResolver(&fakeResolver{provider: gitprovider.NewFake()}), nil, nil).
		WithWebhookProvisioner(prov)

	// One registered-with-hook repo (skip) and two without (TZF-style).
	hooked, err := svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "baseline", Repo: "acme/state", Scope: types.GitRepoScopePlatform, IsDefault: true,
	}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	store.repos["tzf-1"] = &types.TenantGitRepo{ID: "tzf-1", OrgID: "org:1", Name: "tzf-baseline", Repo: "acme/tzf-state", Scope: types.GitRepoScopePlatform}
	store.repos["tzf-2"] = &types.TenantGitRepo{ID: "tzf-2", OrgID: "org:2", Name: "other-org", Repo: "other/state", Scope: types.GitRepoScopePlatform}

	n, err := svc.ReconcileWebhooks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("provisioned = %d, want 2", n)
	}
	for _, id := range []string{"tzf-1", "tzf-2"} {
		if store.repos[id].WebhookURL == "" {
			t.Errorf("repo %s not provisioned", id)
		}
	}
	// The already-hooked repo was not re-provisioned by the sweep.
	callsForHooked := 0
	for _, c := range prov.calls {
		if c == hooked.ID {
			callsForHooked++
		}
	}
	if callsForHooked != 1 { // 1 = registration-time only
		t.Errorf("provision calls for hooked repo = %d, want 1 (registration only)", callsForHooked)
	}

	// Per-repo failure doesn't abort the sweep; the repo is retried next time.
	prov.err = errors.New("provider down")
	store.repos["tzf-3"] = &types.TenantGitRepo{ID: "tzf-3", OrgID: "org:1", Name: "tzf-third", Repo: "acme/third", Scope: types.GitRepoScopePlatform}
	if _, err := svc.ReconcileWebhooks(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.repos["tzf-3"].WebhookURL != "" {
		t.Error("failed provision must leave the repo unprovisioned")
	}
	prov.err = nil
	if _, err := svc.ReconcileWebhooks(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.repos["tzf-3"].WebhookURL == "" {
		t.Error("retry must provision the failed repo")
	}

	// Disabled wiring: sweep is a no-op.
	svcOff := NewService(newFakeStore(), repoResolver(&fakeResolver{provider: gitprovider.NewFake()}), nil, nil)
	n, err = svcOff.ReconcileWebhooks(context.Background())
	if err != nil || n != 0 {
		t.Errorf("disabled sweep = %d, %v, want 0 nil", n, err)
	}
}

// WebhookProvisioningStatus surfaces the registration state on repo
// responses: disabled when no provisioner is wired (KEK or
// INARI_WEBHOOK_BASE_URL unset), provisioned once the hook URL is
// recorded, unprovisioned otherwise (the sweeper retries; repair via
// POST .../git-repos/{id}/webhook).
func TestWebhookProvisioningStatus(t *testing.T) {
	newSvc := func(withProvisioner bool) *Service {
		svc := NewService(newFakeStore(), repoResolver(&fakeResolver{provider: gitprovider.NewFake()}), nil, nil)
		if withProvisioner {
			svc.WithWebhookProvisioner(&fakeProvisioner{})
		}
		return svc
	}
	if got := newSvc(false).WebhookProvisioningStatus(&types.TenantGitRepo{WebhookURL: "https://hook"}); got != "disabled" {
		t.Errorf("no provisioner = %q, want disabled (even with a stored hook URL)", got)
	}
	if got := newSvc(true).WebhookProvisioningStatus(&types.TenantGitRepo{WebhookURL: "https://hook"}); got != "provisioned" {
		t.Errorf("hook URL recorded = %q, want provisioned", got)
	}
	if got := newSvc(true).WebhookProvisioningStatus(&types.TenantGitRepo{}); got != "unprovisioned" {
		t.Errorf("no hook URL = %q, want unprovisioned", got)
	}
}

// Explicit EnsureWebhook (re)provisions; disabled wiring is a typed error
// (501 at the API).
func TestEnsureWebhookEndpoint(t *testing.T) {
	store := newFakeStore()
	prov := &fakeProvisioner{}
	svc := NewService(store, repoResolver(&fakeResolver{provider: gitprovider.NewFake()}), nil, nil).
		WithWebhookProvisioner(prov)
	row := registerPlatformRepo(t, svc)
	callsBefore := len(prov.calls)

	st, err := svc.EnsureWebhook(context.Background(), "org:1", row.ID, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Provisioned || st.HookURL == "" {
		t.Errorf("status = %+v", st)
	}
	if len(prov.calls) != callsBefore+1 {
		t.Errorf("provision calls = %d, want %d (rotation re-provisions)", len(prov.calls), callsBefore+1)
	}

	// Unknown repo → not found.
	if _, err := svc.EnsureWebhook(context.Background(), "org:1", "missing", "user:u1"); err == nil {
		t.Error("want error for unknown repo")
	}

	// Disabled: no provisioner.
	svcOff := NewService(store, repoResolver(&fakeResolver{provider: gitprovider.NewFake()}), nil, nil)
	if _, err := svcOff.EnsureWebhook(context.Background(), "org:1", row.ID, "user:u1"); !errors.Is(err, ErrWebhookDisabled) {
		t.Errorf("err = %v, want ErrWebhookDisabled", err)
	}
}
