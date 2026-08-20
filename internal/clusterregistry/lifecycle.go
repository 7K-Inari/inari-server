// Cluster lifecycle management (plan §5.11): cordon blocks new deploys
// while existing workloads keep running; decommission drains Inari-managed
// resources (ownership-checked — no shared-tenant resources by default,
// §10), revokes the cluster's OIDC client, and archives the audit trail.
package clusterregistry

import (
	"errors"

	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrInvalidTransition is returned for a lifecycle transition the state
// machine does not allow.
var ErrInvalidTransition = errors.New("clusterregistry: invalid lifecycle transition")

// ErrSharedResources blocks decommission when the cluster still holds
// resources Inari does not manage (observe-only/ignored brownfield
// resources — §10: no shared-tenant resources by default).
var ErrSharedResources = errors.New("clusterregistry: cluster holds non-Inari-managed resources")

// clusterTransitions is the lifecycle state machine (plan §5.11).
var clusterTransitions = map[types.ClusterState][]types.ClusterState{
	types.ClusterStatePendingApproval:     {types.ClusterStatePendingRegistration, types.ClusterStateRevoked},
	types.ClusterStatePendingRegistration: {types.ClusterStateActive, types.ClusterStateRevoked},
	types.ClusterStateActive:              {types.ClusterStateDegraded, types.ClusterStateCordoned, types.ClusterStateDecommissioned, types.ClusterStateRevoked},
	types.ClusterStateDegraded:            {types.ClusterStateActive, types.ClusterStateCordoned, types.ClusterStateDecommissioned},
	types.ClusterStateCordoned:            {types.ClusterStateActive, types.ClusterStateDecommissioned},
	types.ClusterStateRevoked:             {types.ClusterStateDecommissioned},
	types.ClusterStateDecommissioned:      {},
}

// CanClusterTransition reports whether the lifecycle state machine allows
// the from -> to transition.
func CanClusterTransition(from, to types.ClusterState) bool {
	for _, s := range clusterTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// CheckDrainOwnership enforces the §10 ownership semantics before a
// decommission drains a cluster: only Inari-managed (adopt) instances are
// drained; any observe-only/ignored instance blocks the drain unless force
// is set. Returns the IDs of the instances to drain in reverse-dependency
// (reverse creation) order — the caller passes instances in creation order.
func CheckDrainOwnership(instances []types.ResourceInstance, force bool) ([]string, error) {
	var shared []string
	for _, in := range instances {
		if in.ManagementMode != types.ManagementModeAdopt {
			shared = append(shared, in.ID)
		}
	}
	if len(shared) > 0 && !force {
		return nil, ErrSharedResources
	}
	drained := make([]string, 0, len(instances))
	for i := len(instances) - 1; i >= 0; i-- {
		if instances[i].ManagementMode == types.ManagementModeAdopt {
			drained = append(drained, instances[i].ID)
		}
	}
	return drained, nil
}
