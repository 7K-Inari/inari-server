//go:build integration

package platformresources_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestEnsureBaseResources(t *testing.T) {
	svc, database := itSetup(t)
	ctx := context.Background()
	org := &types.Organization{ID: "org:1", Slug: "acme", KeycloakOrgID: "kc-1"}

	if err := svc.EnsureBaseResources(ctx, org); err != nil {
		t.Fatal(err)
	}
	rows, err := svc.List(ctx, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	byKind := map[types.PlatformResourceKind]types.PlatformResource{}
	for _, r := range rows {
		if r.Status != types.PlatformStatusReconciling {
			t.Errorf("%s status = %q, want reconciling", r.Kind, r.Status)
		}
		byKind[r.Kind] = r
	}
	if byKind[types.PlatformKindKeycloakRealm].Name != "acme" {
		t.Errorf("keycloak-realm name = %q", byKind[types.PlatformKindKeycloakRealm].Name)
	}
	var dnsDesired map[string]string
	if err := json.Unmarshal(byKind[types.PlatformKindDNSZone].Desired, &dnsDesired); err != nil {
		t.Fatal(err)
	}
	if dnsDesired["mode"] != "shared-record" {
		t.Errorf("dns-zone desired = %s", byKind[types.PlatformKindDNSZone].Desired)
	}
	if byKind[types.PlatformKindTenantNamespace].Name != "tenant-acme" {
		t.Errorf("tenant-namespace name = %q", byKind[types.PlatformKindTenantNamespace].Name)
	}

	// Backfill-safe: a second run adds no rows and emits no new events.
	if err := svc.EnsureBaseResources(ctx, org); err != nil {
		t.Fatal(err)
	}
	if got := countOutbox(t, database, types.EventPlatformResourceStatus); got != 3 {
		t.Errorf("outbox events = %d, want still 3", got)
	}
	var n int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM platform_resources WHERE org_id = 'org:1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("rows = %d, want 3", n)
	}
}
