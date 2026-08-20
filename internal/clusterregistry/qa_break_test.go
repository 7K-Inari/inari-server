package clusterregistry

import (
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestQATransitionTerminalStates(t *testing.T) {
	if CanClusterTransition(types.ClusterStateDecommissioned, types.ClusterStateActive) {
		t.Fatal("decommissioned must be terminal")
	}
	if CanClusterTransition(types.ClusterStatePendingApproval, types.ClusterStateCordoned) {
		t.Fatal("pending cluster must not be cordonable")
	}
	if !CanClusterTransition(types.ClusterStateRevoked, types.ClusterStateDecommissioned) {
		t.Fatal("revoked cluster must still be decommissionable (audit archive path)")
	}
	if CanClusterTransition(types.ClusterStateCordoned, types.ClusterStateDegraded) {
		t.Fatal("cordoned cannot go straight to degraded (uncordon returns to active)")
	}
}
