package gitwebhook

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/7K-Inari/inari-server/internal/cryptoenvelope"
	"github.com/7K-Inari/inari-server/internal/db"
)

// ErrWebhookNotProvisioned: the repo row exists but has no webhook secret
// (no hook was ever registered). The ingress answers 404 — deliveries to
// an unprovisioned repo cannot be authenticated.
var ErrWebhookNotProvisioned = errors.New("gitwebhook: repo has no webhook provisioned")

// WebhookSecretRepo is the narrow inventory seam the vault needs.
type WebhookSecretRepo interface {
	SetGitRepoWebhook(ctx context.Context, q db.Querier, id string, secretEnc, dekEnc []byte, externalID, url string) error
	GitRepoWebhookSecret(ctx context.Context, q db.Querier, id string) (secretEnc, dekEnc []byte, found bool, err error)
}

// SecretStore is the per-repo webhook secret vault (migration 0028
// envelope pattern: fresh DEK per write wrapped by the platform KEK, AAD
// "tenant_git_repos:<id>" binding ciphertext to its row).
type SecretStore struct {
	cipher *cryptoenvelope.Cipher
	repo   WebhookSecretRepo
}

// NewSecretStore builds the vault from the platform KEK.
func NewSecretStore(kek []byte, repo WebhookSecretRepo) (*SecretStore, error) {
	c, err := cryptoenvelope.New(kek)
	if err != nil {
		return nil, err
	}
	return &SecretStore{cipher: c, repo: repo}, nil
}

// GenerateSecret returns a fresh 32-byte webhook secret.
func GenerateSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("gitwebhook: generate secret: %w", err)
	}
	return b, nil
}

// SecretString renders a secret for provider APIs (GitHub's hook config
// takes a string). base64url keeps it URL/header-safe.
func SecretString(secret []byte) string { return base64.RawURLEncoding.EncodeToString(secret) }

// Put encrypts secret and persists the ciphertext plus the provider hook
// registration (externalID/url may be empty for secret-only writes).
func (s *SecretStore) Put(ctx context.Context, q db.Querier, repoID string, secret []byte, externalID, url string) error {
	dataEnc, dekEnc, err := s.cipher.Encrypt(secret, aad(repoID))
	if err != nil {
		return err
	}
	return s.repo.SetGitRepoWebhook(ctx, q, repoID, dataEnc, dekEnc, externalID, url)
}

// Load decrypts the repo's webhook secret.
func (s *SecretStore) Load(ctx context.Context, q db.Querier, repoID string) ([]byte, error) {
	dataEnc, dekEnc, found, err := s.repo.GitRepoWebhookSecret(ctx, q, repoID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrWebhookNotProvisioned
	}
	plain, err := s.cipher.Decrypt(dataEnc, dekEnc, aad(repoID))
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func aad(repoID string) []byte { return []byte("tenant_git_repos:" + repoID) }
