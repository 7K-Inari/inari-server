package deploymentplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
)

var ErrManagedChartNativeConflict = errors.New("managed_chart_native_observability_conflict")

// ApplyManagedChartOverlay applies server-owned values after user values. It
// rejects rather than silently accepting an attempt to provision a second
// chart-native copy of the observability resources.
func ApplyManagedChartOverlay(raw json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var spec map[string]any
	if err := dec.Decode(&spec); err != nil {
		return nil, invalidPlanInput("deployment spec must be a JSON object: %v", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, invalidPlanInput("deployment spec must contain one JSON object")
	}
	if spec == nil {
		spec = map[string]any{}
	}
	obs, ok := spec["observability"].(map[string]any)
	if !ok {
		if _, exists := spec["observability"]; exists {
			return nil, invalidPlanInput("observability must be an object")
		}
		obs = map[string]any{}
		spec["observability"] = obs
	}
	if enabled, exists := obs["enabled"]; exists && enabled == true {
		return nil, ErrManagedChartNativeConflict
	}
	obs["enabled"] = false
	rules, ok := obs["rules"].(map[string]any)
	if !ok {
		if _, exists := obs["rules"]; exists {
			return nil, invalidPlanInput("observability.rules must be an object")
		}
		rules = map[string]any{}
		obs["rules"] = rules
	}
	if enabled, exists := rules["enabled"]; exists && enabled == true {
		return nil, ErrManagedChartNativeConflict
	}
	rules["enabled"] = false
	return json.Marshal(spec)
}

func BuildPackRenderIntent(capability *observability.Capability, selection json.RawMessage, orgSlug, ownerTeam string) (*RenderIntent, error) {
	if capability == nil {
		return nil, invalidPlanInput("observability capability is required")
	}
	dec := json.NewDecoder(bytes.NewReader(selection))
	dec.DisallowUnknownFields()
	var selected struct {
		Folder     string                   `json:"folder"`
		Datasource string                   `json:"datasource"`
		Evaluation observability.Evaluation `json:"evaluation"`
	}
	if err := dec.Decode(&selected); err != nil {
		return nil, invalidPlanInput("invalid provider-normalized selection: %v", err)
	}
	if selected.Folder == "" || selected.Datasource == "" || orgSlug == "" || ownerTeam == "" {
		return nil, invalidPlanInput("folder, datasource, org, and owner team are required")
	}
	if selected.Evaluation != observability.EvaluationCentral && selected.Evaluation != observability.EvaluationLocal {
		return nil, invalidPlanInput("evaluation must be central or local")
	}
	supported := false
	ruleFound := false
	for _, target := range capability.Targets {
		supported = supported || target == selected.Evaluation
	}
	for _, rule := range capability.Rules {
		ruleFound = ruleFound || rule.Evaluation == selected.Evaluation
	}
	if !supported || !ruleFound {
		return nil, invalidPlanInput("capability does not support %s dashboard/rule rendering", selected.Evaluation)
	}
	packSpec := map[string]any{
		"org": orgSlug, "namespace": "monitoring", "app": capability.App, "team": ownerTeam,
		"folder": selected.Folder, "datasource": selected.Datasource, "render": "all",
		"rulesLocal":   selected.Evaluation == observability.EvaluationLocal,
		"rulesCentral": selected.Evaluation == observability.EvaluationCentral,
	}
	return &RenderIntent{PackSpec: packSpec, Evaluation: selected.Evaluation}, nil
}

func Fingerprint(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}
