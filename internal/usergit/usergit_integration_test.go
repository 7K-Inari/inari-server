//go:build integration

package usergit_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
	"github.com/7K-Inari/inari-server/internal/usergit"
)

// --- fixtures -------------------------------------------------------------

type fakeProvider struct {
	mu          sync.Mutex
	refreshes   int
	revokes     int
	refreshErr  error
	revokeErr   error
	exchangeTTL time.Duration // access-token lifetime granted at exchange
	refreshTTL  time.Duration
}

func (p *fakeProvider) Name() string { return "fakehub" }

func (p *fakeProvider) AuthorizeURL(state, codeChallenge, apiBase string) (string, error) {
	return "https://fakehub.example/login/oauth/authorize?state=" + url.QueryEscape(state) +
		"&code_challenge=" + url.QueryEscape(codeChallenge), nil
}

func (p *fakeProvider) Exchange(_ context.Context, code, _, _ string) (*usergit.TokenGrant, error) {
	if code != "good-code" {
		return nil, errors.New("bad code")
	}
	return &usergit.TokenGrant{
		AccessToken: "acc-exchange", RefreshToken: "rt-0",
		ProviderLogin: "octo", Scopes: "repo",
		AccessExpiry: time.Now().Add(p.exchangeTTL),
	}, nil
}

func (p *fakeProvider) Refresh(_ context.Context, refreshToken, _ string) (*usergit.TokenGrant, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.refreshErr != nil {
		return nil, p.refreshErr
	}
	p.refreshes++
	n := p.refreshes
	return &usergit.TokenGrant{
		AccessToken: fmt.Sprintf("acc-%d", n), RefreshToken: fmt.Sprintf("rt-%d", n),
		ProviderLogin: "octo", Scopes: "repo",
		AccessExpiry: time.Now().Add(p.refreshTTL),
	}, nil
}

func (p *fakeProvider) Revoke(_ context.Context, _, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revokes++
	return p.revokeErr
}

func (p *fakeProvider) refreshCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshes
}

func (p *fakeProvider) revokeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revokes
}

func itDB(t *testing.T) *db.DB {
	t.Helper()
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("inari"),
		postgres.WithUsername("inari"),
		postgres.WithPassword("inari"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
	)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	url, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES
		 ('org:1','acme','Acme','kc-1'), ('org:2','other','Other','kc-2')`); err != nil {
		t.Fatal(err)
	}
	return database
}

func itService(t *testing.T, d *db.DB, p usergit.Provider) (*usergit.Service, *usergit.Cipher) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	kek, err := usergit.NewStaticKEK(key)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := usergit.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := usergit.NewService(d, usergit.NewStore(), audit.NewStore(), cipher,
		map[string]usergit.Provider{
			"fakehub": p,
			"gitlab":  usergit.PlannedProvider{ProviderName: "gitlab"},
		},
		[]byte("test-state-key-test-state-key-32!!"), usergit.Config{UIReturnURL: "https://ui.example/settings/git"})
	if err != nil {
		t.Fatal(err)
	}
	return svc, cipher
}

// connect drives the full authorize→callback flow for (org, user).
func connect(t *testing.T, svc *usergit.Service, orgID, userSub string) *usergit.Connection {
	t.Helper()
	ctx := context.Background()
	authURL, err := svc.BeginAuthorize(ctx, orgID, userSub, "fakehub", "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" || u.Query().Get("code_challenge") == "" {
		t.Fatalf("authorize URL missing state/challenge: %s", authURL)
	}
	conn, err := svc.CompleteAuthorize(ctx, userSub, state, "good-code")
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func decryptRefresh(t *testing.T, d *db.DB, cipher *usergit.Cipher, orgID, userSub string) string {
	t.Helper()
	row, err := usergit.NewStore().GetEncrypted(context.Background(), d.Pool, orgID, userSub, "fakehub")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cipher.Decrypt(row.RefreshTokenEnc, row.DEKEnc, "user_git_connections:"+row.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer usergit.Zero(plain)
	return string(plain)
}

func auditCount(t *testing.T, d *db.DB, action string) int {
	t.Helper()
	var n int
	if err := d.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// --- store / lifecycle ----------------------------------------------------

func TestConnectListReconnect(t *testing.T) {
	d := itDB(t)
	p := &fakeProvider{exchangeTTL: time.Hour}
	svc, cipher := itService(t, d, p)
	ctx := context.Background()

	conn := connect(t, svc, "org:1", "user-1")
	if conn.ProviderLogin != "octo" || conn.Provider != "fakehub" {
		t.Fatalf("conn = %+v", conn)
	}
	if got := decryptRefresh(t, d, cipher, "org:1", "user-1"); got != "rt-0" {
		t.Fatalf("stored refresh = %q, want rt-0", got)
	}
	if auditCount(t, d, "user_git.connected") != 1 {
		t.Error("missing user_git.connected audit")
	}

	list, err := svc.List(ctx, "org:1", "user-1")
	if err != nil || len(list) != 1 {
		t.Fatalf("list: n=%d err=%v", len(list), err)
	}

	// Reconnect replaces the row (same unique key, new ID + new ciphertext).
	conn2 := connect(t, svc, "org:1", "user-1")
	if conn2.ID == conn.ID {
		t.Error("reconnect kept the old row ID")
	}
	list, _ = svc.List(ctx, "org:1", "user-1")
	if len(list) != 1 || list[0].ID != conn2.ID {
		t.Fatalf("after reconnect: %+v", list)
	}
}

func TestTenantIsolation(t *testing.T) {
	d := itDB(t)
	p := &fakeProvider{exchangeTTL: time.Hour}
	svc, _ := itService(t, d, p)
	ctx := context.Background()
	connect(t, svc, "org:1", "user-1")

	// Same user_sub in another org sees nothing and cannot mint tokens.
	if list, _ := svc.List(ctx, "org:2", "user-1"); len(list) != 0 {
		t.Fatalf("cross-org list leaked %d rows", len(list))
	}
	if _, err := svc.AccessToken(ctx, "org:2", "user-1", "fakehub"); !errors.Is(err, usergit.ErrNotFound) {
		t.Errorf("cross-org access: err = %v, want ErrNotFound", err)
	}
	if err := svc.Disconnect(ctx, "user-1", "org:2", "user-1", "fakehub"); !errors.Is(err, usergit.ErrNotFound) {
		t.Errorf("cross-org disconnect: err = %v, want ErrNotFound", err)
	}
	// Another user in the same org sees nothing either.
	if list, _ := svc.List(ctx, "org:1", "user-2"); len(list) != 0 {
		t.Fatalf("cross-user list leaked %d rows", len(list))
	}
}

func TestStateBoundToUser(t *testing.T) {
	d := itDB(t)
	p := &fakeProvider{exchangeTTL: time.Hour}
	svc, _ := itService(t, d, p)
	ctx := context.Background()
	authURL, err := svc.BeginAuthorize(ctx, "org:1", "user-1", "fakehub", "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	// A different authenticated user cannot redeem user-1's state.
	if _, err := svc.CompleteAuthorize(ctx, "user-2", u.Query().Get("state"), "good-code"); !errors.Is(err, usergit.ErrStateInvalid) {
		t.Fatalf("err = %v, want ErrStateInvalid", err)
	}
}

// --- refresh machinery ----------------------------------------------------

func TestAccessTokenCacheAndRefresh(t *testing.T) {
	d := itDB(t)
	p := &fakeProvider{exchangeTTL: time.Hour, refreshTTL: time.Hour}
	svc, cipher := itService(t, d, p)
	ctx := context.Background()
	connect(t, svc, "org:1", "user-1")

	tok, err := svc.AccessToken(ctx, "org:1", "user-1", "fakehub")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "acc-1" || p.refreshCount() != 1 {
		t.Fatalf("tok=%q refreshes=%d", tok, p.refreshCount())
	}
	// Second call hits the in-memory cache: no new provider refresh.
	tok2, err := svc.AccessToken(ctx, "org:1", "user-1", "fakehub")
	if err != nil || tok2 != "acc-1" {
		t.Fatalf("cached tok=%q err=%v", tok2, err)
	}
	if p.refreshCount() != 1 {
		t.Fatalf("refreshes = %d, want 1 (cache hit)", p.refreshCount())
	}
	// The rotated refresh token was persisted.
	if got := decryptRefresh(t, d, cipher, "org:1", "user-1"); got != "rt-1" {
		t.Fatalf("stored refresh = %q, want rt-1", got)
	}
	// last_used_at was stamped.
	var lastUsed *time.Time
	if err := d.Pool.QueryRow(ctx,
		`SELECT last_used_at FROM user_git_connections WHERE org_id='org:1' AND user_sub='user-1'`).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if lastUsed == nil {
		t.Error("last_used_at not stamped")
	}
}

func TestRefreshRotationRace(t *testing.T) {
	d := itDB(t)
	p := &fakeProvider{exchangeTTL: -time.Minute, refreshTTL: time.Hour} // force immediate refresh
	svc, cipher := itService(t, d, p)
	ctx := context.Background()
	connect(t, svc, "org:1", "user-1")

	const n = 8
	var wg sync.WaitGroup
	toks := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			toks[i], errs[i] = svc.AccessToken(ctx, "org:1", "user-1", "fakehub")
		}(i)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if toks[i] != toks[0] {
			t.Fatalf("token mismatch: %q vs %q", toks[i], toks[0])
		}
	}
	if got := p.refreshCount(); got != 1 {
		t.Fatalf("refreshes = %d, want 1 (single-flight)", got)
	}
	if got := decryptRefresh(t, d, cipher, "org:1", "user-1"); got != "rt-1" {
		t.Fatalf("stored refresh = %q, want rt-1 (persisted before use)", got)
	}
}

func TestRefreshReplayWipesConnection(t *testing.T) {
	d := itDB(t)
	p := &fakeProvider{exchangeTTL: -time.Minute, refreshTTL: time.Hour}
	svc, _ := itService(t, d, p)
	ctx := context.Background()
	conn := connect(t, svc, "org:1", "user-1")
	_ = conn
	p.refreshErr = usergit.ErrGrantInvalid

	_, err := svc.AccessToken(ctx, "org:1", "user-1", "fakehub")
	if !errors.Is(err, usergit.ErrConnectionCompromised) {
		t.Fatalf("err = %v, want ErrConnectionCompromised", err)
	}
	// Row wiped.
	if _, err := usergit.NewStore().GetEncrypted(ctx, d.Pool, "org:1", "user-1", "fakehub"); !errors.Is(err, usergit.ErrNotFound) {
		t.Fatalf("row after compromise: err = %v, want ErrNotFound", err)
	}
	if auditCount(t, d, "user_git.compromised") != 1 {
		t.Error("missing user_git.compromised audit")
	}
	var n int
	if err := d.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE event_type = $1`, "user_git.compromised").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Error("missing user_git.compromised outbox event")
	}
}

// --- disconnect -----------------------------------------------------------

func TestDisconnectRevokesAndDeletes(t *testing.T) {
	d := itDB(t)
	p := &fakeProvider{exchangeTTL: time.Hour, refreshTTL: time.Hour}
	svc, _ := itService(t, d, p)
	ctx := context.Background()
	connect(t, svc, "org:1", "user-1")

	if err := svc.Disconnect(ctx, "user-1", "org:1", "user-1", "fakehub"); err != nil {
		t.Fatal(err)
	}
	if p.revokeCount() != 1 {
		t.Errorf("revokes = %d, want 1", p.revokeCount())
	}
	if _, err := usergit.NewStore().GetEncrypted(ctx, d.Pool, "org:1", "user-1", "fakehub"); !errors.Is(err, usergit.ErrNotFound) {
		t.Errorf("row after disconnect: err = %v", err)
	}
	if auditCount(t, d, "user_git.disconnected") != 1 {
		t.Error("missing user_git.disconnected audit")
	}
}

func TestDisconnectRevokeFailureStillDeletes(t *testing.T) {
	d := itDB(t)
	p := &fakeProvider{exchangeTTL: time.Hour, refreshTTL: time.Hour, revokeErr: errors.New("provider down")}
	svc, _ := itService(t, d, p)
	ctx := context.Background()
	connect(t, svc, "org:1", "user-1")
	if err := svc.Disconnect(ctx, "user-1", "org:1", "user-1", "fakehub"); err != nil {
		t.Fatal(err)
	}
	if _, err := usergit.NewStore().GetEncrypted(ctx, d.Pool, "org:1", "user-1", "fakehub"); !errors.Is(err, usergit.ErrNotFound) {
		t.Errorf("row after disconnect: err = %v", err)
	}
}

// --- HTTP surface ---------------------------------------------------------

type itValidator struct{}

func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "good":
		return &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}, nil
	case "outsider":
		return &authn.Identity{Subject: "user-9", Organizations: []string{"other"}}, nil
	}
	return nil, errors.New("invalid token")
}

type itAuthorizer struct{ allow bool }

func (a itAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return a.allow, nil
}
func (a itAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type itTenants map[string]*types.Organization

func (t itTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if o, ok := t[slug]; ok {
		return o, nil
	}
	return nil, tenancy.ErrOrgNotFound
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestUserGitHTTP(t *testing.T) {
	d := itDB(t)
	p := &fakeProvider{exchangeTTL: time.Hour, refreshTTL: time.Hour}
	svc, _ := itService(t, d, p)
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, d)
	usergit.NewHandler(svc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := noRedirectClient()

	req := func(method, path, token, body string) *http.Response {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		r, err := http.NewRequest(method, srv.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		r.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 401 unauthenticated, 403 non-member.
	if resp := req("GET", "/api/v1/tenants/acme/git-connections", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauth: %d", resp.StatusCode)
	}
	if resp := req("GET", "/api/v1/tenants/acme/git-connections", "outsider", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("outsider: %d", resp.StatusCode)
	}

	// Unknown provider → 404; planned provider → 501.
	if resp := req("POST", "/api/v1/tenants/acme/git-connections/bitbucket/authorize", "good", "{}"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown provider: %d", resp.StatusCode)
	}
	if resp := req("POST", "/api/v1/tenants/acme/git-connections/gitlab/authorize", "good", "{}"); resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("planned provider: %d", resp.StatusCode)
	}

	// Authorize → 302 with state + PKCE challenge.
	resp := req("POST", "/api/v1/tenants/acme/git-connections/fakehub/authorize", "good", "{}")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" || u.Query().Get("code_challenge") == "" {
		t.Fatalf("authorize location missing state/challenge: %s", loc)
	}

	// Callback with a tampered state → 302 error=state_invalid.
	resp = req("GET", "/api/v1/tenants/acme/git-connections/fakehub/callback?code=good-code&state=garbage.sig", "good", "")
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "error=state_invalid") {
		t.Fatalf("bad-state callback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()

	// Happy-path callback → 302 connected=fakehub.
	resp = req("GET", "/api/v1/tenants/acme/git-connections/fakehub/callback?code=good-code&state="+url.QueryEscape(state), "good", "")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	loc = resp.Header.Get("Location")
	resp.Body.Close()
	if !strings.HasPrefix(loc, "https://ui.example/settings/git?") || !strings.Contains(loc, "connected=fakehub") {
		t.Fatalf("callback location: %s", loc)
	}

	// List shows metadata and leaks no token material.
	resp = req("GET", "/api/v1/tenants/acme/git-connections", "good", "")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "octo") {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	for _, secret := range []string{"rt-0", "acc-exchange", "refresh_token", "access_token"} {
		if strings.Contains(string(body), secret) {
			t.Errorf("list response leaks %q: %s", secret, body)
		}
	}

	// Replay of the same state is impossible (row exists, but state is
	// single-use) — covered at the service layer; here disconnect → 204.
	resp = req("DELETE", "/api/v1/tenants/acme/git-connections/fakehub", "good", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("disconnect: %d", resp.StatusCode)
	}
	resp.Body.Close()
	if p.revokeCount() != 1 {
		t.Errorf("revokes = %d, want 1", p.revokeCount())
	}
	// Second disconnect → 404.
	resp = req("DELETE", "/api/v1/tenants/acme/git-connections/fakehub", "good", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("re-disconnect: %d", resp.StatusCode)
	}
	resp.Body.Close()
}
