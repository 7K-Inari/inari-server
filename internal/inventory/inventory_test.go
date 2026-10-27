package inventory

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestDeriveState(t *testing.T) {
	cases := map[string]types.InstanceState{
		"healthy":     types.InstanceStateRunning,
		"degraded":    types.InstanceStateDegraded,
		"missing":     types.InstanceStateDegraded,
		"progressing": types.InstanceStateDeploying,
		"unknown":     types.InstanceStateDeploying,
		"":            types.InstanceStateDeploying,
	}
	for health, want := range cases {
		if got := deriveState(health); got != want {
			t.Errorf("deriveState(%q) = %q, want %q", health, got, want)
		}
	}
}

func TestInstanceIDForAppRef(t *testing.T) {
	id, ok := instanceIDForAppRef(types.ResourceRef{Kind: "Application", Name: "inari-web-1", Namespace: "argocd"})
	if !ok || id != "web-1" {
		t.Errorf("got %q, %v", id, ok)
	}
	// Parsing stays verbatim (legacy lowercase IDs like "web-1" exist);
	// the canonical-uppercase retry for lowercased ULID names happens at
	// lookup time in applyAppStatus.
	id, ok = instanceIDForAppRef(types.ResourceRef{Kind: "Application", Name: "inari-01j5z8k2n4xqj4tvdmx7a3b2c1", Namespace: "argocd"})
	if !ok || id != "01j5z8k2n4xqj4tvdmx7a3b2c1" {
		t.Errorf("lowercase ULID parse: got %q, %v", id, ok)
	}
	if _, ok := instanceIDForAppRef(types.ResourceRef{Kind: "WebService", Name: "inari-web-1"}); ok {
		t.Error("non-Application kind must not map")
	}
	if _, ok := instanceIDForAppRef(types.ResourceRef{Kind: "Application", Name: "unrelated"}); ok {
		t.Error("non inari- prefix must not map")
	}
}

func TestAddonIDForAppRef(t *testing.T) {
	cases := []struct {
		name   string
		ref    types.ResourceRef
		wantID string
		wantOK bool
	}{
		{"single-cluster addon app", types.ResourceRef{Kind: "Application", Name: "inari-addon-01J5Z8K2N4XQJ4TVDMX7A3B2C1"}, "01J5Z8K2N4XQJ4TVDMX7A3B2C1", true},
		// On-cluster names are lowercased (RFC 1123); parsing normalizes
		// back to the canonical uppercase ULID.
		{"lowercase on-cluster name", types.ResourceRef{Kind: "Application", Name: "inari-addon-01j5z8k2n4xqj4tvdmx7a3b2c1"}, "01J5Z8K2N4XQJ4TVDMX7A3B2C1", true},
		{"lowercase appset child", types.ResourceRef{Kind: "Application", Name: "inari-addon-01j5z8k2n4xqj4tvdmx7a3b2c1-prod-eu"}, "01J5Z8K2N4XQJ4TVDMX7A3B2C1", true},
		{"fleet applicationset", types.ResourceRef{Kind: "ApplicationSet", Name: "inari-addonset-01J5Z8K2N4XQJ4TVDMX7A3B2C1"}, "01J5Z8K2N4XQJ4TVDMX7A3B2C1", true},
		{"appset child app", types.ResourceRef{Kind: "Application", Name: "inari-addon-01J5Z8K2N4XQJ4TVDMX7A3B2C1-prod-eu"}, "01J5Z8K2N4XQJ4TVDMX7A3B2C1", true},
		{"plain instance app", types.ResourceRef{Kind: "Application", Name: "inari-web-1"}, "", false},
		{"unrelated kind", types.ResourceRef{Kind: "WebService", Name: "inari-addon-01J5Z8K2N4XQJ4TVDMX7A3B2C1"}, "", false},
		{"unrelated name", types.ResourceRef{Kind: "Application", Name: "cert-manager"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := addonIDForAppRef(tc.ref)
			if id != tc.wantID || ok != tc.wantOK {
				t.Errorf("addonIDForAppRef(%+v) = %q, %v; want %q, %v", tc.ref, id, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

func TestAppInstanceState(t *testing.T) {
	cases := []struct {
		health, sync string
		want         types.InstanceState
	}{
		{"healthy", "synced", types.InstanceStateRunning},
		{"healthy", "", types.InstanceStateRunning},          // sync unknown to old agents: keep contract
		{"healthy", "error", types.InstanceStateDeploying},   // bogus healthy: never synced
		{"healthy", "unknown", types.InstanceStateDeploying}, // render failure (missing CRD / unreadable repo)
		{"degraded", "outofsync", types.InstanceStateDegraded},
		{"unknown", "unknown", types.InstanceStateDeploying},
	}
	for _, c := range cases {
		if got := appInstanceState(c.health, c.sync); got != c.want {
			t.Errorf("appInstanceState(%q,%q) = %q, want %q", c.health, c.sync, got, c.want)
		}
	}
}
