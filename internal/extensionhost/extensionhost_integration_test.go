//go:build integration

package extensionhost_test

import (
	"context"
	"errors"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/extensionhost"
	"github.com/7K-Inari/inari-server/internal/types"
)

func itService(t *testing.T) *extensionhost.Service {
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
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1')`); err != nil {
		t.Fatal(err)
	}
	return extensionhost.NewService(database, extensionhost.NewStore(), audit.NewStore())
}

func TestExtensionRegistryLifecycle(t *testing.T) {
	svc := itService(t)
	ctx := context.Background()

	e, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{
		OrgID: "org:1", Name: "argocd", Version: "0.1.0", Endpoint: "http://127.0.0.1:9001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.State != types.ExtensionStatePending {
		t.Fatalf("state = %q, want pending", e.State)
	}

	got, err := svc.Get(ctx, "org:1", e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "argocd" || got.Kind != types.ExtensionKindBackend {
		t.Fatalf("got %+v", got)
	}
	if _, err := svc.Get(ctx, "org:2", e.ID); !errors.Is(err, extensionhost.ErrNotFound) {
		t.Errorf("cross-org get = %v, want ErrNotFound", err)
	}

	if err := svc.SetState(ctx, "system:extensionhost", e.ID, types.ExtensionStateReady); err != nil {
		t.Fatal(err)
	}
	got, _ = svc.Get(ctx, "org:1", e.ID)
	if got.State != types.ExtensionStateReady {
		t.Errorf("state = %q, want ready", got.State)
	}
	if err := svc.SetState(ctx, "system:extensionhost", e.ID, "bogus"); err == nil {
		t.Error("expected invalid state error")
	}

	list, err := svc.List(ctx, "org:1")
	if err != nil || len(list) != 1 {
		t.Errorf("list = %v, %v", list, err)
	}

	if err := svc.Unregister(ctx, "user-1", "org:1", e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, "org:1", e.ID); !errors.Is(err, extensionhost.ErrNotFound) {
		t.Errorf("get after unregister = %v, want ErrNotFound", err)
	}
}

func TestExtensionRegisterValidation(t *testing.T) {
	svc := itService(t)
	ctx := context.Background()
	if _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{OrgID: "org:1", Name: "x"}); err == nil {
		t.Error("expected version required error")
	}
	if _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{Name: "x", Version: "1"}); err == nil {
		t.Error("expected orgID required error")
	}
	if _, err := svc.Register(ctx, "user-1", extensionhost.RegisterInput{
		OrgID: "org:1", Name: "x", Version: "1", Kind: "ui",
	}); err == nil {
		t.Error("expected kind error")
	}
}
