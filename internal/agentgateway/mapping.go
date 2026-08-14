package agentgateway

import (
	"google.golang.org/protobuf/types/known/structpb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/types"
)

func mapKind(k agentv1.CapabilityKind) types.CapabilityKind {
	switch k {
	case agentv1.CapabilityKind_CAPABILITY_KIND_CRD:
		return types.CapabilityKindCRD
	case agentv1.CapabilityKind_CAPABILITY_KIND_OLM_CSV:
		return types.CapabilityKindOLMCSV
	case agentv1.CapabilityKind_CAPABILITY_KIND_CROSSPLANE_XRD:
		return types.CapabilityKindCrossplaneXRD
	case agentv1.CapabilityKind_CAPABILITY_KIND_CROSSPLANE_PROVIDER:
		return types.CapabilityKindCrossplaneProvider
	case agentv1.CapabilityKind_CAPABILITY_KIND_KRO_RGD:
		return types.CapabilityKindKRORGD
	case agentv1.CapabilityKind_CAPABILITY_KIND_HELM_RELEASE:
		return types.CapabilityKindHelmRelease
	case agentv1.CapabilityKind_CAPABILITY_KIND_CLUSTER_ADDON:
		return types.CapabilityKindClusterAddon
	case agentv1.CapabilityKind_CAPABILITY_KIND_CLUSTER_METADATA:
		return types.CapabilityKindClusterMetadata
	}
	return ""
}

func mapMode(m agentv1.ManagementMode) types.ManagementMode {
	switch m {
	case agentv1.ManagementMode_MANAGEMENT_MODE_ADOPT:
		return types.ManagementModeAdopt
	case agentv1.ManagementMode_MANAGEMENT_MODE_IGNORE:
		return types.ManagementModeIgnore
	default:
		return types.ManagementModeObserveOnly
	}
}

func mapAction(a agentv1.CapabilityAction) types.CapabilityAction {
	if a == agentv1.CapabilityAction_CAPABILITY_ACTION_DELETE {
		return types.CapabilityActionDelete
	}
	return types.CapabilityActionUpsert
}

func structJSON(s *structpb.Struct) []byte {
	if s == nil {
		return nil
	}
	raw, err := s.MarshalJSON()
	if err != nil {
		return nil
	}
	return raw
}

// mapCapabilityUpdate converts the contract message to the internal ingest
// type. Unknown capability kinds are dropped (compatibility contract: an N-1
// agent may send types we do not know — drop-and-log, never fatal).
func mapCapabilityUpdate(upd *agentv1.CapabilityUpdate) types.CapabilityIngest {
	out := types.CapabilityIngest{
		FullSync:      upd.FullSync,
		StateChecksum: upd.StateChecksum,
	}
	for _, c := range upd.Capabilities {
		kind := mapKind(c.Kind)
		if kind == "" {
			continue
		}
		out.Items = append(out.Items, types.CapabilityItem{
			Kind:           kind,
			Name:           c.Name,
			Group:          c.Group,
			Version:        c.Version,
			Schema:         structJSON(c.Schema),
			UIHints:        structJSON(c.UiHints),
			ManagementMode: mapMode(c.ManagementMode),
			Action:         mapAction(c.Action),
		})
	}
	return out
}
