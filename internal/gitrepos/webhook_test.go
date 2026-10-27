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
