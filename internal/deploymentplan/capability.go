package deploymentplan

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	"gopkg.in/yaml.v3"
)

var (
	ErrCapabilityMetadataMissing = errors.New("capability_metadata_missing")
	ErrCapabilityConflict        = errors.New("capability_conflict")
	ErrPackRenderContract        = errors.New("pack_render_contract_unsupported")
)

func NormalizeCapability(raw []byte) (*observability.Capability, string, error) {
	capability, err := observability.DecodeCapability(raw)
	if err != nil {
		return nil, "", err
	}
	digest, err := capability.Digest()
	if err != nil {
		return nil, "", err
	}
	return capability, digest, nil
}

func CapabilityFromCatalogPayload(payload json.RawMessage, chartMetadata []byte) (*observability.Capability, string, error) {
	var body struct {
		ObservabilityYAML string                       `json:"observabilityYaml"`
		ObservabilityRef  *observability.PackReference `json:"observabilityRef"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, "", fmt.Errorf("catalog capability payload: %w", err)
	}
	raw := []byte(body.ObservabilityYAML)
	if len(chartMetadata) > 0 {
		raw = chartMetadata
	}
	if len(raw) == 0 {
		if body.ObservabilityRef != nil {
			return nil, "", ErrCapabilityMetadataMissing
		}
		return nil, "", nil
	}
	capability, digest, err := NormalizeCapability(raw)
	if err != nil {
		return nil, "", err
	}
	if body.ObservabilityRef != nil && *body.ObservabilityRef != capability.ObservabilityPack {
		return nil, "", fmt.Errorf("%w: package.yaml and signed capability pack references differ", ErrCapabilityConflict)
	}
	if len(chartMetadata) > 0 && len(body.ObservabilityYAML) > 0 {
		_, packageDigest, err := NormalizeCapability([]byte(body.ObservabilityYAML))
		if err != nil || packageDigest != digest {
			return nil, "", fmt.Errorf("%w: package and chart capability metadata differ", ErrCapabilityConflict)
		}
	}
	return capability, digest, nil
}

func CapabilityFromTemplatePayload(payload json.RawMessage) (*observability.Capability, string, error) {
	var body struct {
		Manifest struct {
			Kind          string          `json:"kind"`
			Observability json.RawMessage `json:"observability"`
		} `json:"manifest"`
		ObservabilityYAML string `json:"observabilityYaml"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, "", fmt.Errorf("template capability payload: %w", err)
	}
	declared := len(body.Manifest.Observability) > 0 && string(body.Manifest.Observability) != "null"
	if body.Manifest.Kind == "gitops-repo" {
		if declared || body.ObservabilityYAML != "" {
			return nil, "", errors.New("pure gitops-repo templates cannot provision observability")
		}
		return nil, "", nil
	}
	if !declared {
		return nil, "", nil
	}
	if body.ObservabilityYAML == "" {
		return nil, "", ErrCapabilityMetadataMissing
	}
	return NormalizeCapability([]byte(body.ObservabilityYAML))
}

func ValidatePackRGD(raw []byte, pin PackPin, capability *observability.Capability) error {
	if capability == nil {
		return errors.New("capability is required for pack validation")
	}
	if pin.RenderContract != observability.PackRenderContractV2 || !strings.HasPrefix(pin.Digest, "sha256:") || len(pin.Digest) != 71 {
		return ErrPackRenderContract
	}
	if err := capability.ValidatePackVersion(pin.Version); err != nil {
		return err
	}
	var document struct {
		Kind     string `yaml:"kind"`
		Metadata struct {
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"metadata"`
		Spec struct {
			Schema struct {
				Spec map[string]any `yaml:"spec"`
			} `yaml:"schema"`
			Resources []struct {
				IncludeWhen []string `yaml:"includeWhen"`
			} `yaml:"resources"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("%w: invalid RGD: %v", ErrPackRenderContract, err)
	}
	if document.Kind != "ResourceGraphDefinition" || document.Metadata.Annotations["inari.dev/observability-render-contract"] != observability.PackRenderContractV2 {
		return ErrPackRenderContract
	}
	for _, name := range []string{"org", "namespace", "app", "team", "folder", "datasource", "render", "rulesLocal", "rulesCentral"} {
		if _, ok := document.Spec.Schema.Spec[name]; !ok {
			return fmt.Errorf("%w: pack schema is missing %s", ErrPackRenderContract, name)
		}
	}
	usesLocal, usesCentral := false, false
	for _, resource := range document.Spec.Resources {
		for _, expression := range resource.IncludeWhen {
			usesLocal = usesLocal || strings.Contains(expression, "schema.spec.rulesLocal")
			usesCentral = usesCentral || strings.Contains(expression, "schema.spec.rulesCentral")
		}
	}
	if !usesLocal || !usesCentral {
		return fmt.Errorf("%w: evaluation booleans are not effective in pack resources", ErrPackRenderContract)
	}
	return nil
}
