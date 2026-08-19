//go:build integration

package tenancy_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type fakeIdP struct {
	orgs   map[string]string
	groups []string
	nextID int
}

func newFakeIdP() *fakeIdP { return &fakeIdP{orgs: map[string]string{}} }

func (f *fakeIdP) CreateOrganization(_ context.Context, alias, _ string) (string, error) {
	f.nextID++
	id := fmt.Sprintf("kc-%s-%d", alias, f.nextID)
	f.orgs[id] = alias
	return id, nil
}
func (f *fakeIdP) DeleteOrganization(_ context.Context, id string) error {
	delete(f.orgs, id)
	return nil
}
func (f *fakeIdP) CreateGroup(_ context.Context, path string) (string, error) {
	f.groups = append(f.groups, path)
	return "grp-" + path, nil
}
func (f *fakeIdP) ListOrganizations(context.Context, string) ([]string, error) { return nil, nil }

type recordingStore struct{ written []authz.Tuple }

func (r *recordingStore) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (r *recordingStore) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (r *recordingStore) WriteTuples(_ context.Context, t []authz.Tuple) error {
	r.written = append(r.written, t...)
	return nil
}
func (r *recordingStore) DeleteTuples(context.Context, []authz.Tuple) error { return nil }

func setupDB(t *testing.T) *db.DB {
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
	return database
}

func TestCreateTenantEndToEnd(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())

	org, teams, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme Corp")
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if !strings.HasPrefix(org.ID, "org:kc-acme") {
		t.Errorf("org.ID = %q", org.ID)
	}
	if len(teams) != 3 {
		t.Fatalf("teams = %d, want 3", len(teams))
	}
	if teams[0].KeycloakGroupPath != "tenant-acme/platform-team" {
		t.Errorf("group path = %q", teams[0].KeycloakGroupPath)
	}
	if len(idp.groups) != 3 {
		t.Errorf("keycloak groups created = %v", idp.groups)
	}

	// Audit rows exist.
	events, err := audit.NewStore().List(ctx, database.Pool, org.ID, 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(events) != 4 { // 3 teams + 1 tenant
		t.Errorf("audit events = %d, want 4", len(events))
	}

	// Outbox row pending, then dispatched into tuples.
	rec := &recordingStore{}
	disp := audit.NewDispatcher(database, 50*time.Millisecond, authz.NewTupleWriter(rec))
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(rec.written) != 3 {
		t.Fatalf("tuples written = %v", rec.written)
	}
	if rec.written[0].Object != authz.OrgObject(org.ID) {
		t.Errorf("tuple object = %q", rec.written[0].Object)
	}

	// No unpublished rows remain.
	var pending int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE published_at IS NULL`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Errorf("pending outbox rows = %d", pending)
	}
}

func TestCreateTenantDuplicateSlugRollsBackKeycloak(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	if _, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	_, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme Again")
	if !errors.Is(err, tenancy.ErrSlugTaken) {
		t.Fatalf("err = %v, want ErrSlugTaken", err)
	}
	if len(idp.orgs) != 1 {
		t.Errorf("keycloak orgs after compensation = %v, want 1", idp.orgs)
	}
}

func TestAuditEventsAppendOnly(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `DELETE FROM audit_events WHERE org_id = $1`, org.ID); err == nil {
		t.Error("expected append-only trigger to reject DELETE")
	}
	if _, err := database.Pool.Exec(ctx, `UPDATE audit_events SET actor = 'x' WHERE org_id = $1`, org.ID); err == nil {
		t.Error("expected append-only trigger to reject UPDATE")
	}
}

var _ = types.Organization{} // keep import if unused in future edits
