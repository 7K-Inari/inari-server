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
