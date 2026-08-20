package clusterregistry

import (
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestCanClusterTransition(t *testing.T) {
	allowed := [][2]types.ClusterState{
		{types.ClusterStatePendingApproval, types.ClusterStatePendingRegistration},
		{types.ClusterStatePendingApproval, types.ClusterStateRevoked},
		{types.ClusterStatePendingRegistration, types.ClusterStateActive},
		{types.ClusterStatePendingRegistration, types.ClusterStateRevoked},
		{types.ClusterStateActive, types.ClusterStateDegraded},
		{types.ClusterStateDegraded, types.ClusterStateActive},
		{types.ClusterStateActive, types.ClusterStateCordoned},
		{types.ClusterStateDegraded, types.ClusterStateCordoned},
		{types.ClusterStateCordoned, types.ClusterStateActive},
		{types.ClusterStateActive, types.ClusterStateDecommissioned},
		{types.ClusterStateDegraded, types.ClusterStateDecommissioned},
		{types.ClusterStateCordoned, types.ClusterStateDecommissioned},
		{types.ClusterStateRevoked, types.ClusterStateDecommissioned},
		{types.ClusterStateActive, types.ClusterStateRevoked},
	}
	for _, tr := range allowed {
		if !CanClusterTransition(tr[0], tr[1]) {
			t.Errorf("transition %s -> %s should be allowed", tr[0], tr[1])
		}
	}

	denied := [][2]types.ClusterState{
		{types.ClusterStateDecommissioned, types.ClusterStateActive},
		{types.ClusterStateDecommissioned, types.ClusterStateCordoned},
		{types.ClusterStateRevoked, types.ClusterStateActive},
		{types.ClusterStateCordoned, types.ClusterStateDegraded},
		{types.ClusterStatePendingApproval, types.ClusterStateActive},
		{types.ClusterStatePendingRegistration, types.ClusterStateCordoned},
		{types.ClusterStateActive, types.ClusterStatePendingRegistration},
		{types.ClusterStateCordoned, types.ClusterStateRevoked},
	}
	for _, tr := range denied {
		if CanClusterTransition(tr[0], tr[1]) {
			t.Errorf("transition %s -> %s should be denied", tr[0], tr[1])
		}
	}
}

func TestCheckDrainOwnership(t *testing.T) {
	adopted := types.ResourceInstance{ID: "i1", ManagementMode: types.ManagementModeAdopt}
	observed := types.ResourceInstance{ID: "i2", ManagementMode: types.ManagementModeObserveOnly}
	ignored := types.ResourceInstance{ID: "i3", ManagementMode: types.ManagementModeIgnore}

	drained, err := CheckDrainOwnership([]types.ResourceInstance{adopted}, false)
	if err != nil {
		t.Fatalf("all-adopted instances should drain: %v", err)
	}
	if len(drained) != 1 || drained[0] != "i1" {
		t.Errorf("drained = %v, want [i1]", drained)
	}

	_, err = CheckDrainOwnership([]types.ResourceInstance{adopted, observed}, false)
	if !errors.Is(err, ErrSharedResources) {
		t.Errorf("observe-only instance must block drain, got %v", err)
	}
	_, err = CheckDrainOwnership([]types.ResourceInstance{ignored}, false)
	if !errors.Is(err, ErrSharedResources) {
		t.Errorf("ignored instance must block drain, got %v", err)
	}

	drained, err = CheckDrainOwnership([]types.ResourceInstance{adopted, observed}, true)
	if err != nil {
		t.Fatalf("force must override ownership block: %v", err)
	}
	if len(drained) != 1 || drained[0] != "i1" {
		t.Errorf("force drain = %v, want only adopted [i1]", drained)
	}
}
