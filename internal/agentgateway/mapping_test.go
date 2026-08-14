package agentgateway

import (
	"testing"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestMapKind(t *testing.T) {
	cases := map[agentv1.CapabilityKind]types.CapabilityKind{
		agentv1.CapabilityKind_CAPABILITY_KIND_CRD:                 types.CapabilityKindCRD,
		agentv1.CapabilityKind_CAPABILITY_KIND_OLM_CSV:             types.CapabilityKindOLMCSV,
		agentv1.CapabilityKind_CAPABILITY_KIND_CROSSPLANE_XRD:      types.CapabilityKindCrossplaneXRD,
		agentv1.CapabilityKind_CAPABILITY_KIND_CROSSPLANE_PROVIDER: types.CapabilityKindCrossplaneProvider,
		agentv1.CapabilityKind_CAPABILITY_KIND_KRO_RGD:             types.CapabilityKindKRORGD,
		agentv1.CapabilityKind_CAPABILITY_KIND_HELM_RELEASE:        types.CapabilityKindHelmRelease,
		agentv1.CapabilityKind_CAPABILITY_KIND_CLUSTER_ADDON:       types.CapabilityKindClusterAddon,
		agentv1.CapabilityKind_CAPABILITY_KIND_CLUSTER_METADATA:    types.CapabilityKindClusterMetadata,
		agentv1.CapabilityKind_CAPABILITY_KIND_UNSPECIFIED:         "",
		agentv1.CapabilityKind(999):                                "",
	}
	for in, want := range cases {
		if got := mapKind(in); got != want {
			t.Errorf("mapKind(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestMapModeDefaultsToObserveOnly(t *testing.T) {
	if got := mapMode(agentv1.ManagementMode_MANAGEMENT_MODE_UNSPECIFIED); got != types.ManagementModeObserveOnly {
		t.Errorf("mapMode(unspecified) = %q, want observe-only", got)
	}
	if got := mapMode(agentv1.ManagementMode_MANAGEMENT_MODE_ADOPT); got != types.ManagementModeAdopt {
		t.Errorf("mapMode(adopt) = %q", got)
	}
}

func TestMapCapabilityUpdateDropsUnknownKinds(t *testing.T) {
	upd := &agentv1.CapabilityUpdate{
		FullSync:      true,
		StateChecksum: "sum1",
		Capabilities: []*agentv1.Capability{
			{Kind: agentv1.CapabilityKind_CAPABILITY_KIND_CRD, Name: "foos.example.com", Group: "example.com", Version: "v1"},
			{Kind: agentv1.CapabilityKind(999), Name: "unknown"},
		},
	}
	got := mapCapabilityUpdate(upd)
	if !got.FullSync || got.StateChecksum != "sum1" {
		t.Errorf("metadata lost: %+v", got)
	}
	if len(got.Items) != 1 {
		t.Fatalf("items = %d, want 1 (unknown dropped)", len(got.Items))
	}
	if got.Items[0].Action != types.CapabilityActionUpsert {
		t.Errorf("default action = %q, want upsert", got.Items[0].Action)
	}
}
