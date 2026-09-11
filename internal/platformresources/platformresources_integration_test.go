//go:build integration

package platformresources_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

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

	// Empty name is rejected before touching the database.
	if _, err := svc.EnsureDesired(ctx, "org:1", types.PlatformKindKeycloakRealm, "", nil); err == nil {
		t.Error("EnsureDesired empty name: want error, got nil")
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

func TestEnsureDesiredConcurrent(t *testing.T) {
	svc, database := itSetup(t)
	ctx := context.Background()

	// Simultaneous upserts of the same (org, kind, name) must not error or
	// create duplicate rows.
	const workers = 8
	errs := make(chan error, workers)
	ids := make(chan string, workers)
	for i := 0; i < workers; i++ {
		go func() {
			r, err := svc.EnsureDesired(ctx, "org:1", types.PlatformKindDNSZone, "acme.example.com", nil)
			if err != nil {
				errs <- err
				return
			}
			ids <- r.ID
		}()
	}
	var firstID string
	for i := 0; i < workers; i++ {
		select {
		case err := <-errs:
			t.Fatalf("concurrent EnsureDesired: %v", err)
		case id := <-ids:
			if firstID == "" {
				firstID = id
			} else if id != firstID {
				t.Errorf("id = %q, want stable id %q", id, firstID)
			}
		}
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
	svc, database := itSetup(t)
	ctx := context.Background()

	r, err := svc.EnsureDesired(ctx, "org:1", types.PlatformKindTenantNamespace, "acme-apps", nil)
	if err != nil {
		t.Fatal(err)
	}
	// EnsureDesired emitted its own outbox event; the status update adds one.
	before := countOutbox(t, database, types.EventPlatformResourceStatus)

	observed := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	matched, err := svc.ApplyStatus(ctx, "cluster-1", platformresources.StatusUpdate{
		Resource:   types.ResourceRef{Kind: "TenantNamespace.platform.inari.io", Name: "acme-apps"},
		Health:     "healthy",
		Message:    "namespace provisioned",
		ObservedAt: observed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("ApplyStatus matched = false, want true")
	}

	got, err := svc.Get(ctx, "org:1", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != types.PlatformStatusReady || got.Detail != "namespace provisioned" {
		t.Errorf("status/detail = %q/%q, want ready/namespace provisioned", got.Status, got.Detail)
	}
	if got.ReportedAt == nil || !got.ReportedAt.Equal(observed) {
		t.Errorf("reported_at = %v, want %v", got.ReportedAt, observed)
	}

	// Audit + outbox from the agent update.
	if n := countOutbox(t, database, types.EventPlatformResourceStatus); n != before+1 {
		t.Errorf("outbox events = %d, want %d", n, before+1)
	}
	var actor, action string
	if err := database.Pool.QueryRow(ctx,
		`SELECT actor, action FROM audit_events WHERE object_id = $1 AND action = 'platform-resource.status' ORDER BY created_at DESC LIMIT 1`, r.ID).
		Scan(&actor, &action); err != nil {
		t.Fatal(err)
	}
	if actor != "agent:cluster-1" || action != "platform-resource.status" {
		t.Errorf("audit actor/action = %q/%q, want agent:cluster-1/platform-resource.status", actor, action)
	}

	// Degraded health maps to failed.
	if _, err := svc.ApplyStatus(ctx, "cluster-1", platformresources.StatusUpdate{
		Resource: types.ResourceRef{Kind: "TenantNamespace.platform.inari.io", Name: "acme-apps"},
		Health:   "degraded",
		Message:  "quota exceeded",
	}); err != nil {
		t.Fatal(err)
	}
	got, err = svc.Get(ctx, "org:1", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != types.PlatformStatusFailed {
		t.Errorf("status = %q, want failed", got.Status)
	}

	// Unmatched (kind, name) is drop-and-log: no error, matched=false, no
	// audit/outbox rows.
	events := countOutbox(t, database, types.EventPlatformResourceStatus)
	matched, err = svc.ApplyStatus(ctx, "cluster-1", platformresources.StatusUpdate{
		Resource: types.ResourceRef{Kind: "KeycloakRealm.platform.inari.io", Name: "never-desired"},
		Health:   "healthy",
	})
	if err != nil {
		t.Fatalf("unmatched update: %v", err)
	}
	if matched {
		t.Error("ApplyStatus unmatched: matched = true, want false")
	}
	if n := countOutbox(t, database, types.EventPlatformResourceStatus); n != events {
		t.Errorf("outbox events = %d, want still %d", n, events)
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
}
