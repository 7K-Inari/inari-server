package github

import (
	"context"
	"fmt"
	"net/http"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
)

// EnsureWebhook implements gitprovider.Provider: idempotent repo-hook
// registration (list → patch-or-create). Matching is by hook URL — hooks
// for other consumers (CI etc.) are never touched. The hook secret is
// write-only on GitHub's side, so an existing hook is always re-patched
// with the full desired config (drift is undetectable, and this is what
// makes secret rotation work).
//
// Requires the GitHub App's repository "Webhooks: read & write" permission
// (app manifest change documented in the milestone PR).
func (p *Provider) EnsureWebhook(ctx context.Context, repo string, cfg gitprovider.WebhookConfig) (string, error) {
	owner, name, err := splitRepo(repo)
	if err != nil {
		return "", err
	}
	base := fmt.Sprintf("/repos/%s/%s", owner, name)
	var hooks []struct {
		ID     int64 `json:"id"`
		Config struct {
			URL string `json:"url"`
		} `json:"config"`
	}
	if _, err := p.do(ctx, http.MethodGet, base+"/hooks?per_page=100", nil, &hooks); err != nil {
		return "", err
	}
	desired := map[string]any{
		"active": true,
		"events": cfg.Events,
		"config": map[string]string{
			"url":          cfg.URL,
			"content_type": "json",
			"secret":       cfg.Secret,
			"insecure_ssl": "0",
		},
	}
	for _, h := range hooks {
		if h.Config.URL != cfg.URL {
			continue
		}
		if _, err := p.do(ctx, http.MethodPatch, fmt.Sprintf("%s/hooks/%d", base, h.ID), desired, nil); err != nil {
			return "", err
		}
		return fmt.Sprint(h.ID), nil
	}
	create := map[string]any{"name": "web"}
	for k, v := range desired {
		create[k] = v
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if _, err := p.do(ctx, http.MethodPost, base+"/hooks", create, &created); err != nil {
		return "", err
	}
	return fmt.Sprint(created.ID), nil
}
