package gitwebhook

import (
	"context"
	"fmt"
	"strings"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// hookEvents are the provider events every repo hook subscribes to:
// PR merges (the finalizer) and pushes (Fleet Manager, later).
var hookEvents = []string{"pull_request", "push"}

// Provisioner registers per-repo webhooks: it generates (or rotates) the
// vault-stored secret and ensures the provider-side hook points at the
// public ingress endpoint.
type Provisioner struct {
	secrets *SecretStore
	baseURL string
}

// NewProvisioner wires the provisioner. baseURL is the server's public
// base (INARI_WEBHOOK_BASE_URL); empty disables provisioning (local dev).
func NewProvisioner(secrets *SecretStore, baseURL string) *Provisioner {
	return &Provisioner{secrets: secrets, baseURL: strings.TrimSuffix(baseURL, "/")}
}

// Enabled reports whether provisioning is configured.
func (p *Provisioner) Enabled() bool { return p != nil && p.secrets != nil && p.baseURL != "" }

// IngressURL is the delivery URL registered for a provider.
func (p *Provisioner) IngressURL(provider string) string {
	return p.baseURL + "/api/v1/webhooks/git/" + provider
}

// Provision generates a fresh secret (rotating any existing one),
// registers/updates the provider hook, and persists ciphertext + hook
// registration on the row. The row's WebhookURL/WebhookExternalID fields
// are updated in memory to match.
func (p *Provisioner) Provision(ctx context.Context, q db.Querier, git gitprovider.Provider, repo *types.TenantGitRepo) (string, error) {
	if !p.Enabled() {
		return "", fmt.Errorf("gitwebhook: provisioning disabled (INARI_WEBHOOK_BASE_URL unset)")
	}
	raw, err := GenerateSecret()
	if err != nil {
		return "", err
	}
	// The canonical secret is the base64url STRING's bytes: providers
	// take the string and HMAC with those exact bytes, so the vault must
	// store the same form for verification to match.
	secret := []byte(SecretString(raw))
	url := p.IngressURL(string(repo.Provider))
	hookID, err := git.EnsureWebhook(ctx, repo.Repo, gitprovider.WebhookConfig{
		URL:    url,
		Secret: string(secret),
		Events: hookEvents,
	})
	if err != nil {
		return "", fmt.Errorf("gitwebhook: ensure hook: %w", err)
	}
	if err := p.secrets.Put(ctx, q, repo.ID, secret, hookID, url); err != nil {
		return "", err
	}
	repo.WebhookURL = url
	repo.WebhookExternalID = hookID
	return url, nil
}
