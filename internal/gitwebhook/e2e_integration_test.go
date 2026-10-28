//go:build integration

// Full-chain test: provision a repo webhook (vault + EnsureWebhook),
// receive a signed delivery through the real HTTP router, and consume the
// normalized event from the real outbox — the exact path a GitHub
// pr_merged delivery takes in production (minus JetStream, covered by the
// audit dispatcher's own tests).
package gitwebhook

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

func setupE2E(t *testing.T) (*db.DB, context.Context) {
	t.Helper()
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
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','acme','kc-acme')`); err != nil {
		t.Fatal(err)
	}
	return database, ctx
}

type dbOutbox struct{}

func (dbOutbox) AppendOutbox(ctx context.Context, q db.Querier, orgID, eventType string, payload any) error {
	return audit.AppendOutbox(ctx, q, orgID, eventType, payload)
}

func TestWebhookIngressEndToEnd(t *testing.T) {
	database, ctx := setupE2E(t)
	store := inventory.NewStore()
	kek := bytes.Repeat([]byte{0x07}, 32)
	secrets, err := NewSecretStore(kek, store)
	if err != nil {
		t.Fatal(err)
	}
	git := gitprovider.NewFake()
	prov := NewProvisioner(secrets, "https://inari.example.com")

	// Register + provision a repo (the gitrepos.Register path's effects).
	row := &types.TenantGitRepo{
		OrgID: "org:1", Name: "team-a", Repo: "acme/team-a-gitops",
		Provider: types.GitRepoProviderGitHub, Scope: types.GitRepoScopePlatform, IsDefault: true,
	}
	if err := store.UpsertGitRepo(ctx, database.Pool, row); err != nil {
		t.Fatal(err)
	}
	hookURL, err := prov.Provision(ctx, database.Pool, git, row)
	if err != nil {
		t.Fatal(err)
	}
	if hookURL != "https://inari.example.com/api/v1/webhooks/git/github" {
		t.Errorf("hookURL = %q", hookURL)
	}
	if len(git.Webhooks) != 1 {
		t.Fatalf("provider hook not registered: %+v", git.Webhooks)
	}

	// Serve the ingress through the real router (no bearer token — the
	// HMAC is the credential).
	ing := NewIngress(database.Pool, store, secrets, dbOutbox{})
	router, api := httpserver.NewRouter(slog.Default(), nil, nil)
	NewHandler(ing).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	defer srv.Close()

	secret, err := secrets.Load(ctx, database.Pool, row.ID)
	if err != nil {
		t.Fatal(err)
	}
	body := fixture(t, "github_pr_merged.json")
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/webhooks/git/github", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", sign(secret, body))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}

	// The normalized event must be in the REAL outbox, consumable by the
	// finalizer subscription contract.
	var orgID, eventType string
	var payload []byte
	if err := database.Pool.QueryRow(ctx,
		`SELECT org_id, event_type, payload FROM outbox ORDER BY id DESC LIMIT 1`).Scan(&orgID, &eventType, &payload); err != nil {
		t.Fatal(err)
	}
	if orgID != "org:1" || eventType != string(EventTypePRMerged) {
		t.Errorf("outbox row = %s %s", orgID, eventType)
	}
	var p PRMergedPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Repo != "acme/team-a-gitops" || p.PRNumber != 17 || p.MergeSHA == "" || p.PRURL == "" {
		t.Errorf("payload = %+v", p)
	}

	// The finalizer consumes the row as the dispatcher would deliver it.
	inst := &fakeCompleter{found: true}
	fin := NewMergeFinalizer(inst, &fakeCompleter{}, nil)
	if err := fin.Handle(ctx, &types.OutboxEvent{OrgID: orgID, EventType: eventType, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if len(inst.calls) != 1 || inst.calls[0].prURL != p.PRURL || inst.calls[0].mergeSHA != p.MergeSHA {
		t.Errorf("finalizer calls = %+v", inst.calls)
	}
}

// Wiring-gap probe: a repo row created WITHOUT gitrepos.Register (the TZF
// baseline and legacy git-config mirror paths upsert directly) has no
// webhook — deliveries 404 and PR-policy merges on that repo can never be
// finalized via webhook.
func TestRepoCreatedOutsideRegisterHasNoWebhook(t *testing.T) {
	database, ctx := setupE2E(t)
	store := inventory.NewStore()
	// This is exactly what baselineReposAdapter.EnsureDefaultBaselineRepo
	// (TZF) and syncDefaultRepoFromConfig (legacy PUT git-config) do.
	row := &types.TenantGitRepo{
		OrgID: "org:1", Name: "baseline", Repo: "acme/acme-inari-state",
		Provider: types.GitRepoProviderGitHub, Scope: types.GitRepoScopePlatform,
		CommitPolicy: types.CommitPolicyPullRequest, IsDefault: true,
	}
	if err := store.UpsertGitRepo(ctx, database.Pool, row); err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecretStore(bytes.Repeat([]byte{0x07}, 32), store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secret.Load(ctx, database.Pool, row.ID); err == nil {
		t.Fatal("expected no webhook secret for directly-upserted repo (the wiring gap)")
	}
}
