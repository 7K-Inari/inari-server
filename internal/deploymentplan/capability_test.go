package deploymentplan

import (
	"encoding/json"
	"errors"
	"testing"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	"gopkg.in/yaml.v3"
)

func capabilityYAML(t *testing.T) string {
	t.Helper()
	raw, err := yaml.Marshal(testCapability())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestNormalizeCatalogCapabilityAndCrossCheckPackageReference(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"observabilityYaml": capabilityYAML(t),
		"observabilityRef":  observability.PackReference{Package: "observability-pack", VersionRange: ">=0.2.0 <0.3.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	capability, digest, err := CapabilityFromCatalogPayload(payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if capability.App != "payments-api" || len(digest) != 71 {
		t.Fatalf("normalized capability = %#v, digest %q", capability, digest)
	}
}

func TestCatalogCapabilityConflictAndMissingMetadata(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"observabilityYaml": capabilityYAML(t),
		"observabilityRef":  observability.PackReference{Package: "other-pack", VersionRange: ">=0.2.0 <0.3.0"},
	})
	if _, _, err := CapabilityFromCatalogPayload(payload, nil); !errors.Is(err, ErrCapabilityConflict) {
		t.Fatalf("error = %v, want capability conflict", err)
	}
	refOnly, _ := json.Marshal(map[string]any{"observabilityRef": observability.PackReference{Package: "observability-pack", VersionRange: ">=0.2.0 <0.3.0"}})
	if _, _, err := CapabilityFromCatalogPayload(refOnly, nil); !errors.Is(err, ErrCapabilityMetadataMissing) {
		t.Fatalf("error = %v, want missing metadata", err)
	}
}

func TestTemplateCapabilityAndPureScaffolds(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"manifest":          map[string]any{"kind": "component", "observability": map[string]any{"manifest": "observability/observability.yaml"}},
		"observabilityYaml": capabilityYAML(t),
	})
	capability, _, err := CapabilityFromTemplatePayload(payload)
	if err != nil || capability.App != "payments-api" {
		t.Fatalf("template capability = %#v, %v", capability, err)
	}
	pure, _ := json.Marshal(map[string]any{"manifest": map[string]any{"kind": "gitops-repo"}})
	capability, digest, err := CapabilityFromTemplatePayload(pure)
	if err != nil || capability != nil || digest != "" {
		t.Fatalf("pure scaffold received capability: %#v %q %v", capability, digest, err)
	}
	invalid, _ := json.Marshal(map[string]any{"manifest": map[string]any{"kind": "gitops-repo", "observability": map[string]any{"manifest": "observability/observability.yaml"}}, "observabilityYaml": capabilityYAML(t)})
	if _, _, err := CapabilityFromTemplatePayload(invalid); err == nil {
		t.Fatal("gitops-repo observability accepted")
	}
}

func TestPackRenderContractV2Required(t *testing.T) {
	pin := PackPin{ArtifactPin: ArtifactPin{Version: "0.2.0", Digest: testDigest}, RenderContract: observability.PackRenderContractV2}
	valid := `apiVersion: kro.run/v1alpha1
kind: ResourceGraphDefinition
metadata:
  name: payments-api-observability
  annotations:
    inari.dev/observability-render-contract: inari.observability-pack/v2
spec:
  schema:
    spec:
      org: string
      namespace: string
      app: string
      team: string
      folder: string
      datasource: string
      render: string
      rulesLocal: boolean
      rulesCentral: boolean
  resources:
    - id: central
      includeWhen: ['${schema.spec.rulesCentral}']
    - id: local
      includeWhen: ['${schema.spec.rulesLocal}']
`
	if err := ValidatePackRGD([]byte(valid), pin, testCapability()); err != nil {
		t.Fatalf("valid v2 pack rejected: %v", err)
	}
	pin.RenderContract = "inari.observability-pack/v1"
	if err := ValidatePackRGD([]byte(valid), pin, testCapability()); !errors.Is(err, ErrPackRenderContract) {
		t.Fatalf("error = %v, want render contract rejection", err)
	}
	if err := ValidatePackRGD([]byte("kind: ResourceGraphDefinition\n"), PackPin{ArtifactPin: ArtifactPin{Version: "0.2.0", Digest: testDigest}, RenderContract: observability.PackRenderContractV2}, testCapability()); !errors.Is(err, ErrPackRenderContract) {
		t.Fatalf("missing annotation error = %v", err)
	}
}
