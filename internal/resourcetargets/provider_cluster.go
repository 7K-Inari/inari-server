package resourcetargets

import (
	"encoding/json"
	"fmt"

	"github.com/7K-Inari/inari-server/internal/types"
)

type deploymentClusterProvider struct{}

func (deploymentClusterProvider) Describe() ProviderDescriptor {
	return ProviderDescriptor{
		Capability: CapabilityDeploymentCluster, ResourceKinds: []string{ResourceKindCluster},
		Actions: []Action{ActionView, ActionUse}, ConfigSchema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
		SelectionSchema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
		UISchema:        json.RawMessage(`{"picker":"cluster"}`), SupportsDefault: true,
	}
}

func (deploymentClusterProvider) NormalizeConfig(raw json.RawMessage) (json.RawMessage, error) {
	if !emptyObject(raw) {
		return nil, invalid("config", "deployment.cluster configuration must be empty")
	}
	return json.RawMessage(`{}`), nil
}

func (p deploymentClusterProvider) ValidateRegistration(snapshot ResourceSnapshot, config json.RawMessage) error {
	if _, err := p.NormalizeConfig(config); err != nil {
		return err
	}
	if snapshot.Cluster == nil {
		return invalid("resourceRef", "cluster does not exist")
	}
	return nil
}

func clusterBinding(snapshot ResourceSnapshot) Binding {
	b := Binding{Renderer: RendererArgoCD}
	if snapshot.Cluster != nil {
		b.ClusterID = snapshot.Cluster.ID
	}
	if snapshot.BaselineRepo != nil {
		b.BaselineRepoID = snapshot.BaselineRepo.ID
		b.BaseBranch = snapshot.BaselineRepo.BaseBranch
		b.CommitPolicy = string(snapshot.BaselineRepo.CommitPolicy)
	}
	return b
}

func (p deploymentClusterProvider) Resolve(target *Target, snapshot ResourceSnapshot) (Binding, Readiness, error) {
	if _, err := p.NormalizeConfig(target.Config); err != nil {
		return Binding{}, Readiness{}, err
	}
	binding := clusterBinding(snapshot)
	if snapshot.Cluster == nil || snapshot.Cluster.ID != target.ResourceRef.ID {
		return binding, Readiness{State: ReadinessUnavailable, Reasons: []string{"cluster_not_found"}}, nil
	}
	readiness := Readiness{State: ReadinessReady, ObservedAt: snapshot.Cluster.LastSeenAt}
	switch snapshot.Cluster.State {
	case types.ClusterStateActive:
	case types.ClusterStateDegraded:
		readiness.State = ReadinessDegraded
		readiness.Reasons = []string{"cluster_degraded"}
	default:
		readiness.State = ReadinessUnavailable
		readiness.Reasons = []string{fmt.Sprintf("cluster_%s", snapshot.Cluster.State)}
	}
	return binding, readiness, nil
}

func (deploymentClusterProvider) ValidateSelection(target *Target, selection json.RawMessage) (json.RawMessage, ApprovalPolicy, error) {
	if !emptyObject(selection) {
		return nil, ApprovalPolicy{}, invalid("selection", "deployment.cluster selection must be empty")
	}
	return json.RawMessage(`{}`), ApprovalPolicy{}, nil
}
