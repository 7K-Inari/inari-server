package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
)

func webhookCfg() gitprovider.WebhookConfig {
	return gitprovider.WebhookConfig{
		URL:    "https://inari.example.com/api/v1/webhooks/git/github",
		Secret: "s3cr3t",
		Events: []string{"pull_request", "push"},
	}
}

// No existing hook: EnsureWebhook creates it with the full config.
func TestEnsureWebhookCreatesHook(t *testing.T) {
	var created map[string]any
	var postCalled bool
	p := testProvider(t, mux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/state/hooks":
			_ = json.NewEncoder(w).Encode([]any{})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/state/hooks":
			postCalled = true
			_ = json.NewDecoder(r.Body).Decode(&created)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 42})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	id, err := p.EnsureWebhook(context.Background(), "acme/state", webhookCfg())
	if err != nil {
		t.Fatal(err)
	}
	if id != "42" {
		t.Errorf("hookID = %q, want 42", id)
	}
	if !postCalled {
		t.Fatal("expected POST /repos/acme/state/hooks")
	}
	if created["name"] != "web" || created["active"] != true {
		t.Errorf("hook payload = %v", created)
	}
	events, _ := created["events"].([]any)
	if len(events) != 2 || events[0] != "pull_request" || events[1] != "push" {
		t.Errorf("events = %v, want [pull_request push]", events)
	}
	cfg, _ := created["config"].(map[string]any)
	if cfg["url"] != webhookCfg().URL || cfg["secret"] != "s3cr3t" ||
		cfg["content_type"] != "json" || cfg["insecure_ssl"] != "0" {
		t.Errorf("config = %v", cfg)
	}
}

// An existing hook for the same URL is patched (never duplicated). The
// secret is write-only on GitHub's side, so drift is undetectable and the
// patch always re-sends the full desired config (this is also what makes
// secret rotation work).
func TestEnsureWebhookPatchesExistingHook(t *testing.T) {
	var patchCalled, postCalled bool
	p := testProvider(t, mux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/state/hooks":
			_ = json.NewEncoder(w).Encode([]any{
				map[string]any{"id": 7, "active": true, "events": []string{"push"},
					"config": map[string]any{"url": webhookCfg().URL}},
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/repos/acme/state/hooks/7":
			patchCalled = true
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 7})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/state/hooks":
			postCalled = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 99})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	id, err := p.EnsureWebhook(context.Background(), "acme/state", webhookCfg())
	if err != nil {
		t.Fatal(err)
	}
	if id != "7" {
		t.Errorf("hookID = %q, want 7", id)
	}
	if !patchCalled {
		t.Error("expected PATCH /repos/acme/state/hooks/7")
	}
	if postCalled {
		t.Error("must not create a duplicate hook")
	}
}

// Hooks pointing at OTHER URLs (e.g. a teammate's CI) are left alone.
func TestEnsureWebhookIgnoresForeignHooks(t *testing.T) {
	p := testProvider(t, mux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/state/hooks":
			_ = json.NewEncoder(w).Encode([]any{
				map[string]any{"id": 7, "config": map[string]any{"url": "https://ci.example.com/hook"}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/state/hooks":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 8})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	id, err := p.EnsureWebhook(context.Background(), "acme/state", webhookCfg())
	if err != nil {
		t.Fatal(err)
	}
	if id != "8" {
		t.Errorf("hookID = %q, want 8 (new hook; foreign hook untouched)", id)
	}
}

// API failures surface as APIError.
func TestEnsureWebhookAPIError(t *testing.T) {
	p := testProvider(t, mux(t, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
	}))
	_, err := p.EnsureWebhook(context.Background(), "acme/state", webhookCfg())
	if err == nil {
		t.Fatal("want error")
	}
	if _, ok := err.(*APIError); !ok {
		t.Errorf("err = %T %v, want *APIError", err, err)
	}
}

// The in-memory Fake records EnsureWebhook calls for assertions.
func TestFakeEnsureWebhook(t *testing.T) {
	f := gitprovider.NewFake()
	id, err := f.EnsureWebhook(context.Background(), "acme/state", webhookCfg())
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Error("fake must return a hook ID")
	}
	if len(f.Webhooks) != 1 || f.Webhooks[0].Repo != "acme/state" || f.Webhooks[0].Config.URL != webhookCfg().URL {
		t.Errorf("Webhooks = %+v", f.Webhooks)
	}
	// Idempotent: same repo + URL keeps the same hook.
	id2, err := f.EnsureWebhook(context.Background(), "acme/state", webhookCfg())
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id || len(f.Webhooks) != 2 {
		t.Errorf("second call: id %q (want %q), records %d", id2, id, len(f.Webhooks))
	}
}
