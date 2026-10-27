package gitwebhook

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeRepoLookup resolves repo slugs to registry rows.
type fakeRepoLookup struct {
	rows map[string]*types.TenantGitRepo
}

func (f *fakeRepoLookup) FindGitRepoByRepo(_ context.Context, _ db.Querier, repo string, provider types.GitRepoProvider) (*types.TenantGitRepo, error) {
	key := string(provider) + "/" + repo
	if r, ok := f.rows[key]; ok {
		return r, nil
	}
	return nil, inventory.ErrRepoNotFound
}

// fakeOutbox records appended events.
type fakeOutbox struct {
	events []recordedEvent
	err    error
}

type recordedEvent struct {
	orgID, eventType string
	payload          json.RawMessage
}

func (f *fakeOutbox) AppendOutbox(_ context.Context, _ db.Querier, orgID, eventType string, payload any) error {
	if f.err != nil {
		return f.err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	f.events = append(f.events, recordedEvent{orgID, eventType, raw})
	return nil
}

type ingressEnv struct {
	srv     *httptest.Server
	secrets *SecretStore
	outbox  *fakeOutbox
	repoID  string
}

func newIngressEnv(t *testing.T, provisioned bool) *ingressEnv {
	t.Helper()
	secretRepo := newFakeSecretRepo()
	ss, err := NewSecretStore(testKEK(), secretRepo)
	if err != nil {
		t.Fatal(err)
	}
	row := &types.TenantGitRepo{ID: "repo-1", OrgID: "org:1", Repo: "acme/team-a-gitops", Provider: types.GitRepoProviderGitHub}
	lookup := &fakeRepoLookup{rows: map[string]*types.TenantGitRepo{"github/acme/team-a-gitops": row}}
	if provisioned {
		secret, _ := GenerateSecret()
		if err := ss.Put(context.Background(), nil, row.ID, secret, "hook-1", "https://x/hook"); err != nil {
			t.Fatal(err)
		}
	}
	outbox := &fakeOutbox{}
	ing := NewIngress(nil, lookup, ss, outbox)
	router, api := httpserver.NewRouter(slog.Default(), nil, nil)
	NewHandler(ing).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return &ingressEnv{srv: srv, secrets: ss, outbox: outbox, repoID: row.ID}
}

func (e *ingressEnv) post(t *testing.T, provider, event string, body, secret []byte, tamperSig bool) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+"/api/v1/webhooks/git/"+provider, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if event != "" {
		req.Header.Set("X-GitHub-Event", event)
	}
	if secret != nil {
		sig := sign(secret, body)
		if tamperSig {
			sig = sign([]byte("wrong"), body)
		}
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (e *ingressEnv) secret(t *testing.T) []byte {
	t.Helper()
	s, err := e.secrets.Load(context.Background(), nil, e.repoID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIngressPRMergedAccepted(t *testing.T) {
	e := newIngressEnv(t, true)
	body := fixture(t, "github_pr_merged.json")
	resp := e.post(t, "github", "pull_request", body, e.secret(t), false)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	var out struct {
		Accepted  bool   `json:"accepted"`
		EventType string `json:"eventType"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Accepted || out.EventType != string(EventTypePRMerged) {
		t.Errorf("response = %+v", out)
	}
	if len(e.outbox.events) != 1 {
		t.Fatalf("outbox events = %d, want 1", len(e.outbox.events))
	}
	ev := e.outbox.events[0]
	if ev.orgID != "org:1" || ev.eventType != string(EventTypePRMerged) {
		t.Errorf("outbox = %s %s", ev.orgID, ev.eventType)
	}
	var p PRMergedPayload
	if err := json.Unmarshal(ev.payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Repo != "acme/team-a-gitops" || p.PRNumber != 17 ||
		p.MergeSHA != "6dcb09b5b57875f334f61aebed695e2e4193db5e" || p.BaseBranch != "main" ||
		p.PRURL != "https://github.com/acme/team-a-gitops/pull/17" {
		t.Errorf("payload = %+v", p)
	}
}

func TestIngressPushAccepted(t *testing.T) {
	e := newIngressEnv(t, true)
	body := fixture(t, "github_push.json")
	resp := e.post(t, "github", "push", body, e.secret(t), false)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	if len(e.outbox.events) != 1 || e.outbox.events[0].eventType != string(EventTypePush) {
		t.Fatalf("outbox = %+v", e.outbox.events)
	}
}

func TestIngressUnknownProvider(t *testing.T) {
	e := newIngressEnv(t, true)
	resp := e.post(t, "gitlab", "push", fixture(t, "github_push.json"), nil, false)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestIngressUnknownRepo(t *testing.T) {
	e := newIngressEnv(t, true)
	body := []byte(replaceOnce(string(fixture(t, "github_push.json")), "acme/team-a-gitops", "acme/other"))
	resp := e.post(t, "github", "push", body, e.secret(t), false)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestIngressRepoNotProvisioned(t *testing.T) {
	e := newIngressEnv(t, false)
	resp := e.post(t, "github", "push", fixture(t, "github_push.json"), []byte("any"), false)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestIngressBadSignature(t *testing.T) {
	e := newIngressEnv(t, true)
	body := fixture(t, "github_push.json")
	resp := e.post(t, "github", "push", body, e.secret(t), true)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("tampered: status = %d, want 401", resp.StatusCode)
	}
	if len(e.outbox.events) != 0 {
		t.Error("rejected deliveries must not reach the outbox")
	}

	// Missing signature header.
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/v1/webhooks/git/github", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "push")
	resp2, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing sig: status = %d, want 401", resp2.StatusCode)
	}
}

func TestIngressPingIgnored(t *testing.T) {
	e := newIngressEnv(t, true)
	resp := e.post(t, "github", "ping", fixture(t, "github_ping.json"), e.secret(t), false)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	var out struct {
		Accepted bool `json:"accepted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Accepted {
		t.Error("ping must be accepted:false")
	}
	if len(e.outbox.events) != 0 {
		t.Error("ping must not reach the outbox")
	}
}

// Oversized deliveries are rejected before any DB/HMAC work (the route
// is unauthenticated).
func TestIngressDeliveryTooLarge(t *testing.T) {
	e := newIngressEnv(t, true)
	body := make([]byte, maxDeliverySize+1)
	resp := e.post(t, "github", "push", body, e.secret(t), false)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
	if len(e.outbox.events) != 0 {
		t.Error("oversized deliveries must not reach the outbox")
	}
}

func TestIngressMalformedBody(t *testing.T) {
	e := newIngressEnv(t, true)
	resp := e.post(t, "github", "pull_request", []byte(`{"action":`), e.secret(t), false)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// A disabled ingress (nil deps, export-openapi wiring) answers 501, never panics.
func TestIngressDisabled(t *testing.T) {
	router, api := httpserver.NewRouter(slog.Default(), nil, nil)
	NewHandler(nil).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	defer srv.Close()
	resp, err := srv.Client().Post(srv.URL+"/api/v1/webhooks/git/github", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", resp.StatusCode)
	}
}
