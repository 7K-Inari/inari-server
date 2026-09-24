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
	if _, ok := instanceIDForAppRef(types.ResourceRef{Kind: "WebService", Name: "inari-web-1"}); ok {
		t.Error("non-Application kind must not map")
	}
	if _, ok := instanceIDForAppRef(types.ResourceRef{Kind: "Application", Name: "unrelated"}); ok {
		t.Error("non inari- prefix must not map")
	}
}

func TestAppInstanceState(t *testing.T) {
	cases := []struct {
		health, sync string
		want         types.InstanceState
	}{
		{"healthy", "synced", types.InstanceStateRunning},
		{"healthy", "", types.InstanceStateRunning}, // sync unknown to old agents: keep contract
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
