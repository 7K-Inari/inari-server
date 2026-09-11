package main

import (
	"context"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/agentgateway"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/platformresources"
	"github.com/7K-Inari/inari-server/internal/types"
)

type fakeInventorySink struct{ calls int }

func (f *fakeInventorySink) ApplyStatus(context.Context, string, inventory.StatusUpdate) (bool, error) {
	f.calls++
	return true, nil
}

type fakePlatformSink struct {
	calls int
	got   platformresources.StatusUpdate
}

func (f *fakePlatformSink) ApplyStatus(_ context.Context, _ string, upd platformresources.StatusUpdate) (bool, error) {
	f.calls++
	f.got = upd
	return true, nil
}

func TestStatusSinkRouterRouting(t *testing.T) {
	inv := &fakeInventorySink{}
	plat := &fakePlatformSink{}
	r := statusSinkRouter{inv: inv, plat: plat}
	ctx := context.Background()

	observed := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	platformKinds := []string{
		"KeycloakRealm.platform.inari.io",
		"KeycloakClient.platform.inari.io",
		"DNSZone.platform.inari.io",
		"DNSRecord.platform.inari.io",
		"TenantNamespace.platform.inari.io",
	}
	for _, kind := range platformKinds {
		if _, err := r.ApplyStatus(ctx, "cluster-1", agentgateway.StatusUpdate{
			Resource:   types.ResourceRef{Kind: kind, Name: "acme"},
			Health:     "healthy",
			Message:    "ok",
			ObservedAt: observed,
		}); err != nil {
			t.Fatalf("ApplyStatus(%q): %v", kind, err)
		}
	}
	if plat.calls != len(platformKinds) {
		t.Errorf("platform sink calls = %d, want %d", plat.calls, len(platformKinds))
	}
	if inv.calls != 0 {
		t.Errorf("inventory sink calls = %d, want 0", inv.calls)
	}
	if plat.got.Resource.Name != "acme" || plat.got.Health != "healthy" ||
		plat.got.Message != "ok" || !plat.got.ObservedAt.Equal(observed) {
		t.Errorf("platform update = %+v, want resource/health/message/observedAt forwarded", plat.got)
	}

	// Inventory kinds still route to the inventory sink only.
	if _, err := r.ApplyStatus(ctx, "cluster-1", agentgateway.StatusUpdate{
		Resource: types.ResourceRef{Kind: "Deployment", Name: "web", Namespace: "default"},
		Health:   "degraded",
	}); err != nil {
		t.Fatal(err)
	}
	if inv.calls != 1 {
		t.Errorf("inventory sink calls = %d, want 1", inv.calls)
	}
	if plat.calls != len(platformKinds) {
		t.Errorf("platform sink calls = %d, want still %d", plat.calls, len(platformKinds))
	}
}
