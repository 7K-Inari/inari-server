//go:build integration

package platformresources_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/platformresources"
	"github.com/7K-Inari/inari-server/internal/types"
)

func itSetup(t *testing.T) (*platformresources.Service, *db.DB) {
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
	return platformresources.NewService(database, platformresources.NewStore(), audit.NewStore()), database
}

func countOutbox(t *testing.T, database *db.DB, eventType string) int {
	t.Helper()
	var n int
	if err := database.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM outbox WHERE event_type = $1`, eventType).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEnsureDesiredIdempotent(t *testing.T) {
	svc, database := itSetup(t)
	ctx := context.Background()

	r, err := svc.EnsureDesired(ctx, "org:1", types.PlatformKindKeycloakRealm, "acme", json.RawMessage(`{"realm":"acme"}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != types.PlatformStatusReconciling {
		t.Errorf("status = %q, want reconciling", r.Status)
	}
	if got := countOutbox(t, database, types.EventPlatformResourceStatus); got != 1 {
		t.Fatalf("outbox events = %d, want 1", got)
	}

	// Same desired: no change, no new events.
	r2, err := svc.EnsureDesired(ctx, "org:1", types.PlatformKindKeycloakRealm, "acme", json.RawMessage(`{"realm":"acme"}`))
	if err != nil {
		t.Fatal(err)
	}
	if r2.ID != r.ID {
		t.Errorf("id = %q, want stable id %q", r2.ID, r.ID)
	}
	if got := countOutbox(t, database, types.EventPlatformResourceStatus); got != 1 {
		t.Errorf("outbox events = %d, want still 1", got)
	}

	// Changed desired: update in place, one new event.
	r3, err := svc.EnsureDesired(ctx, "org:1", types.PlatformKindKeycloakRealm, "acme", json.RawMessage(`{"realm":"acme","theme":"inari"}`))
	if err != nil {
		t.Fatal(err)
	}
	if r3.ID != r.ID {
		t.Errorf("id = %q, want stable id %q", r3.ID, r.ID)
	}
	if got := countOutbox(t, database, types.EventPlatformResourceStatus); got != 2 {
		t.Errorf("outbox events = %d, want 2", got)
	}

	var n int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM platform_resources WHERE org_id = 'org:1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}
}

func TestApplyStatusAndGet(t *testing.T) {
	svc, _ := itSetup(t)
	ctx := context.Background()

	r, err := svc.EnsureDesired(ctx, "org:1", types.PlatformKindTenantNamespace, "acme-apps", nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := svc.ApplyStatus(ctx, r.ID, types.PlatformStatusReady, "namespace provisioned")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != types.PlatformStatusReady || got.Detail != "namespace provisioned" {
		t.Errorf("status/detail = %q/%q, want ready/namespace provisioned", got.Status, got.Detail)
	}
	if got.ReportedAt == nil {
		t.Error("reported_at is nil, want set")
	}

	// Cross-tenant get must not leak.
	if _, err := svc.Get(ctx, "org:other", r.ID); err == nil {
		t.Error("Get with wrong org: want error, got nil")
	}

	list, err := svc.List(ctx, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != r.ID {
		t.Errorf("list = %+v, want single row %q", list, r.ID)
	}

	// Unknown id surfaces not-found.
	if _, err := svc.ApplyStatus(ctx, "nope", types.PlatformStatusReady, ""); err == nil {
		t.Error("ApplyStatus unknown id: want error, got nil")
	}
}
