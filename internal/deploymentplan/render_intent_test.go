package deploymentplan

import (
	"encoding/json"
	"errors"
	"testing"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
)

func testCapability() *observability.Capability {
	return &observability.Capability{
		APIVersion: observability.APIVersion, Kind: observability.CapabilityKind,
		App: "payments-api", Folder: "payments-api",
		Datasources: map[string]string{"prometheus": "${DS_PROMETHEUS}"}, LinkVariables: []string{"namespace"},
		Dashboards:      []observability.Dashboard{{Title: "Service overview", UID: "payments-api-overview", File: "dashboards/overview.json"}},
		Rules:           []observability.Rule{{File: "rules/availability.yaml", Evaluation: observability.EvaluationCentral}, {File: "rules/service.yaml", Evaluation: observability.EvaluationLocal}},
		Targets:         []observability.Evaluation{observability.EvaluationCentral, observability.EvaluationLocal},
		SeverityRouting: map[string]string{"critical": "platform-security"}, MinimumAppVersion: ">=1.3.0 <2.0.0",
		ObservabilityPack: observability.PackReference{Package: "observability-pack", VersionRange: ">=0.2.0 <0.3.0"},
	}
}

func TestManagedChartOverlayForcesNativeResourcesOff(t *testing.T) {
	input := json.RawMessage(`{"name":"payments","observability":{"enabled":false,"rules":{"enabled":false}},"replicas":2}`)
	before := append([]byte(nil), input...)
	got, err := ApplyManagedChartOverlay(input)
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(got, &spec); err != nil {
		t.Fatal(err)
	}
	obs := spec["observability"].(map[string]any)
	if obs["enabled"] != false || obs["rules"].(map[string]any)["enabled"] != false || spec["replicas"] != float64(2) {
		t.Fatalf("unexpected managed spec: %#v", spec)
	}
	if string(input) != string(before) {
		t.Fatal("input was mutated")
	}
}

func TestManagedChartOverlayRejectsOptInAndNonObjects(t *testing.T) {
	for _, input := range []string{
		`{"observability":{"enabled":true}}`,
		`{"observability":{"rules":{"enabled":true}}}`,
		`[]`,
	} {
		if _, err := ApplyManagedChartOverlay(json.RawMessage(input)); err == nil {
			t.Fatalf("input %s unexpectedly accepted", input)
		}
	}
	if _, err := ApplyManagedChartOverlay(json.RawMessage(`{"observability":{"enabled":true}}`)); !errors.Is(err, ErrManagedChartNativeConflict) {
		t.Fatalf("error = %v, want managed chart conflict", err)
	}
}

func TestPackRenderIntentCentralAndLocal(t *testing.T) {
	for _, tc := range []struct {
		name       string
		evaluation string
		local      bool
		central    bool
	}{
		{"central", "central", false, true},
		{"local", "local", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selection := json.RawMessage(`{"folder":"acme-inc/payments-api","datasource":"metrics","evaluation":"` + tc.evaluation + `"}`)
			got, err := BuildPackRenderIntent(testCapability(), selection, "acme-inc", "payments-api-maintainers")
			if err != nil {
				t.Fatal(err)
			}
			if got.Evaluation != observability.Evaluation(tc.evaluation) || got.PackSpec["render"] != "all" || got.PackSpec["rulesLocal"] != tc.local || got.PackSpec["rulesCentral"] != tc.central {
				t.Fatalf("render intent = %#v", got)
			}
			if got.PackSpec["folder"] != "acme-inc/payments-api" || got.PackSpec["org"] != "acme-inc" || got.PackSpec["namespace"] != "monitoring" {
				t.Fatalf("pack spec = %#v", got.PackSpec)
			}
		})
	}
}

func TestPackRenderIntentRejectsUnsupportedSelection(t *testing.T) {
	if _, err := BuildPackRenderIntent(testCapability(), json.RawMessage(`{"folder":"acme/payments","datasource":"metrics","evaluation":"central","baseUrl":"https://grafana.example"}`), "acme", "team"); err == nil {
		t.Fatal("arbitrary target binding accepted")
	}
}

func TestFingerprintIsDeterministic(t *testing.T) {
	first := map[string]any{"b": 2, "a": 1}
	second := map[string]any{"a": 1, "b": 2}
	a, err := Fingerprint(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Fingerprint(second)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || len(a) != len("sha256:")+64 {
		t.Fatalf("fingerprints = %q / %q", a, b)
	}
}
