//go:build integration

package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	gitgithub "github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider/github"
	"github.com/7K-Inari/inari-server/internal/types"
)

// seedUserScopeTemplate inserts a catalog version whose manifest declares
// scaffold.scope=user (the preflight reads the catalog payload; the step
// engine re-reads the on-disk manifest).
func seedUserScopeTemplate(t *testing.T, f *itFixture) {
	t.Helper()
	if _, err := f.db.Pool.Exec(context.Background(),
		`INSERT INTO catalog_item_versions (item_id, version, channel, schema, payload) VALUES
		   ('template:go-service','2.0.0','stable',$1::jsonb,'{"manifest":{"tags":["go"],"scaffold":{"scope":"user"}}}')`,
		itSchema); err != nil {
		t.Fatal(err)
	}
}

func userScopeEnv(t *testing.T, dir string, git GitProvider, ug UserGitResolver, cfgs GitConfigResolver) *ExecEnv {
	t.Helper()
	return &ExecEnv{
		Git: git, GitOrg: "acme-platform",
		Registrar: &fakeRegistrar{}, Upsert: &fakeUpserter{}, RBAC: &fakeRBACBinder{},
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(),
		UserGit: ug, GitConfigs: cfgs,
	}
}

func TestCreateRunUserScopeBlockedWithoutConnection(t *testing.T) {
	f := newITFixture(t)
	defer f.srv.Close()
	seedUserScopeTemplate(t, f)
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "2.0.0", userScopeBlock, map[string]string{"a.txt": "x"})
	git := gitprovider.NewFake()
	f.svc.WithExecEnv(userScopeEnv(t, dir, git,
		&fakeUserGit{err: &gitgithub.ErrNoConnection{OrgID: "org:acme", UserSub: "dev-1", Provider: "github"}},
		fakeGitConfigs{}))

	_, _, _, err := f.svc.CreateRun(context.Background(), "dev-1", "org:acme", "go-service", "2.0.0", "", json.RawMessage(`{"name":"payments-api"}`))
	var connReq *ErrGitConnectionRequired
	if !errors.As(err, &connReq) {
		t.Fatalf("err = %v, want ErrGitConnectionRequired", err)
	}
	if connReq.ConnectURL != "/api/v1/tenants/acme/git-connections/github/authorize" {
		t.Fatalf("ConnectURL = %q", connReq.ConnectURL)
	}
}

func TestUserScopeRunFallsBackWithAudit(t *testing.T) {
	f := newITFixture(t)
	defer f.srv.Close()
	seedUserScopeTemplate(t, f)
	ctx := context.Background()
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "2.0.0", userScopeBlock, map[string]string{"a.txt": "x"})
	git := gitprovider.NewFake()
	f.svc.WithExecEnv(userScopeEnv(t, dir, git,
		&fakeUserGit{err: &gitgithub.ErrNoConnection{OrgID: "org:acme", UserSub: "dev-1", Provider: "github"}},
		fakeGitConfigs{"org:acme": {OrgID: "org:acme", Repo: "acme/inari-state", UserTemplateFallback: "platform_app"}}))

	// platform_app policy: run creation is allowed; the fallback happens
	// (and is audited) at execution time.
	run, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "2.0.0", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}
	f.svc.reconcileOnce(ctx, time.Minute)

	got, _, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseCompleted {
		t.Fatalf("phase = %q err=%q, want completed", got.Phase, got.Error)
	}
	if v := outputValue(got.Outputs, "authModel"); v != "platform_fallback" {
		t.Fatalf("authModel = %q, want platform_fallback", v)
	}
	var auditCount, outboxCount int
	if err := f.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'scaffold.git.fallback' AND object_id = $1`, run.ID).
		Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("scaffold.git.fallback audit rows = %d, want 1", auditCount)
	}
	if err := f.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE event_type = 'scaffold.git.fallback'`).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 {
		t.Fatalf("scaffold.git.fallback outbox rows = %d, want 1", outboxCount)
	}
}

func TestUserScopeRunWithConnection(t *testing.T) {
	f := newITFixture(t)
	defer f.srv.Close()
	seedUserScopeTemplate(t, f)
	ctx := context.Background()
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "2.0.0", userScopeBlock, map[string]string{"a.txt": "x"})
	userGit := gitprovider.NewFake()
	platformGit := gitprovider.NewFake()
	f.svc.WithExecEnv(userScopeEnv(t, dir, platformGit, &fakeUserGit{
		provider: userGit,
		info:     &gitprovider.AuthInfo{Model: gitprovider.AuthModelUser, UserSub: "dev-1", ConnectionID: "ugc:1", ProviderLogin: "octocat"},
	}, fakeGitConfigs{}))

	run, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "2.0.0", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}
	f.svc.reconcileOnce(ctx, time.Minute)

	got, _, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseCompleted {
		t.Fatalf("phase = %q err=%q, want completed", got.Phase, got.Error)
	}
	if v := outputValue(got.Outputs, "authModel"); v != "user" {
		t.Fatalf("authModel = %q, want user", v)
	}
	if v := outputValue(got.Outputs, "gitConnectionId"); v != "ugc:1" {
		t.Fatalf("gitConnectionId = %q", v)
	}
	if v := outputValue(got.Outputs, "gitProviderLogin"); v != "octocat" {
		t.Fatalf("gitProviderLogin = %q", v)
	}
	// The platform provider must stay untouched on the user path: the repo
	// was created through the user's connection, not the platform app.
	if _, err := platformGit.ReadFile(ctx, "acme-platform/acme-payments-api", "main", "a.txt"); err == nil {
		t.Fatal("platform provider must not hold the scaffolded repo on the user path")
	}
	if got, err := userGit.ReadFile(ctx, "acme-platform/acme-payments-api", "main", "a.txt"); err != nil || got != "x" {
		t.Fatalf("user provider repo read = %q err=%v", got, err)
	}
	var fallbackCount int
	if err := f.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'scaffold.git.fallback'`).Scan(&fallbackCount); err != nil {
		t.Fatal(err)
	}
	if fallbackCount != 0 {
		t.Fatalf("unexpected fallback audit rows = %d", fallbackCount)
	}
}
