package gitwebhook

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeSecretRepo is an in-memory WebhookSecretRepo.
type fakeSecretRepo struct {
	rows map[string]struct {
		secretEnc, dekEnc []byte
		externalID, url   string
	}
}

func newFakeSecretRepo() *fakeSecretRepo {
	return &fakeSecretRepo{rows: map[string]struct {
		secretEnc, dekEnc []byte
		externalID, url   string
	}{}}
}

func (f *fakeSecretRepo) SetGitRepoWebhook(_ context.Context, _ db.Querier, id string, secretEnc, dekEnc []byte, externalID, url string) error {
	if id == "missing" {
		return inventory.ErrRepoNotFound
	}
	f.rows[id] = struct {
		secretEnc, dekEnc []byte
		externalID, url   string
	}{secretEnc, dekEnc, externalID, url}
	return nil
}

func (f *fakeSecretRepo) GitRepoWebhookSecret(_ context.Context, _ db.Querier, id string) ([]byte, []byte, bool, error) {
	if id == "missing" {
		return nil, nil, false, inventory.ErrRepoNotFound
	}
	r, ok := f.rows[id]
	if !ok || r.secretEnc == nil {
		return nil, nil, false, nil
	}
	return r.secretEnc, r.dekEnc, true, nil
}

func testKEK() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func TestSecretStoreRoundTrip(t *testing.T) {
	repo := newFakeSecretRepo()
	ss, err := NewSecretStore(testKEK(), repo)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.Put(context.Background(), nil, "repo-1", secret, "hook-7", "https://x/hook"); err != nil {
		t.Fatal(err)
	}
	got, err := ss.Load(context.Background(), nil, "repo-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Error("round-trip mismatch")
	}
}

// Secrets are bound to their row (AAD): a ciphertext stored under one repo
// ID must not decrypt under another.
func TestSecretStoreAADBindsRow(t *testing.T) {
	repo := newFakeSecretRepo()
	ss, err := NewSecretStore(testKEK(), repo)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := GenerateSecret()
	if err := ss.Put(context.Background(), nil, "repo-1", secret, "", ""); err != nil {
		t.Fatal(err)
	}
	// Transplant repo-1's ciphertext to repo-2.
	repo.rows["repo-2"] = repo.rows["repo-1"]
	if _, err := ss.Load(context.Background(), nil, "repo-2"); err == nil {
		t.Fatal("transplanted ciphertext must not decrypt")
	}
}

func TestSecretStoreNotProvisioned(t *testing.T) {
	repo := newFakeSecretRepo()
	ss, _ := NewSecretStore(testKEK(), repo)
	if _, err := ss.Load(context.Background(), nil, "repo-1"); !errors.Is(err, ErrWebhookNotProvisioned) {
		t.Errorf("err = %v, want ErrWebhookNotProvisioned", err)
	}
	if _, err := ss.Load(context.Background(), nil, "missing"); !errors.Is(err, inventory.ErrRepoNotFound) {
		t.Errorf("err = %v, want ErrRepoNotFound", err)
	}
}

func TestGenerateSecret(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateSecret()
	if len(a) != 32 {
		t.Errorf("secret length = %d, want 32", len(a))
	}
	if bytes.Equal(a, b) {
		t.Error("secrets must be random")
	}
}

// Provisioner: generates the secret, registers the provider hook, and
// persists ciphertext + hook registration on the row.
func TestProvisionerEndToEnd(t *testing.T) {
	repo := newFakeSecretRepo()
	ss, _ := NewSecretStore(testKEK(), repo)
	prov := NewProvisioner(ss, "https://inari.example.com")
	git := gitprovider.NewFake()
	row := &types.TenantGitRepo{ID: "repo-1", OrgID: "org:1", Repo: "acme/state", Provider: types.GitRepoProviderGitHub}

	hookURL, err := prov.Provision(context.Background(), nil, git, row)
	if err != nil {
		t.Fatal(err)
	}
	wantURL := "https://inari.example.com/api/v1/webhooks/git/github"
	if hookURL != wantURL {
		t.Errorf("hookURL = %q, want %q", hookURL, wantURL)
	}
	if len(git.Webhooks) != 1 {
		t.Fatalf("EnsureWebhook calls = %d, want 1", len(git.Webhooks))
	}
	call := git.Webhooks[0]
	if call.Repo != "acme/state" || call.Config.URL != wantURL {
		t.Errorf("EnsureWebhook = %s %+v", call.Repo, call.Config)
	}
	if len(call.Config.Events) != 2 || call.Config.Events[0] != "pull_request" || call.Config.Events[1] != "push" {
		t.Errorf("events = %v", call.Config.Events)
	}
	// The registered secret must equal the vault-stored one (decrypted).
	stored, err := ss.Load(context.Background(), nil, "repo-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != call.Config.Secret {
		t.Error("registered secret does not match the vault copy")
	}
	if row.WebhookURL != wantURL || row.WebhookExternalID == "" {
		t.Errorf("row webhook fields = %q %q", row.WebhookURL, row.WebhookExternalID)
	}

	// Rotation: a second Provision replaces the secret (the existing hook
	// is patched with the new one — EnsureWebhook is idempotent by URL).
	if _, err := prov.Provision(context.Background(), nil, git, row); err != nil {
		t.Fatal(err)
	}
	rotated, _ := ss.Load(context.Background(), nil, "repo-1")
	if string(rotated) == call.Config.Secret {
		t.Error("rotation must replace the secret")
	}
	if git.Webhooks[1].Config.Secret != string(rotated) {
		t.Error("rotated secret was not registered with the provider")
	}
}
