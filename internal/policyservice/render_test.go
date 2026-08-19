package policyservice

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestRenderPackBundleMultiDoc(t *testing.T) {
	manifests, _ := json.Marshal([]any{
		map[string]any{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata":   map[string]any{"name": "require-labels"},
		},
		map[string]any{
			"apiVersion": "admissionregistration.k8s.io/v1",
			"kind":       "ValidatingAdmissionPolicy",
			"metadata":   map[string]any{"name": "check-replicas"},
		},
	})
	pack := &types.PolicyPack{Manifests: manifests}
	bundle, err := RenderPackBundle(pack)
	if err != nil {
		t.Fatal(err)
	}
	s := string(bundle)
	if !strings.Contains(s, "kind: ClusterPolicy") || !strings.Contains(s, "kind: ValidatingAdmissionPolicy") {
		t.Fatalf("bundle missing docs:\n%s", s)
	}
	if strings.Count(s, "---") != 1 {
		t.Fatalf("expected one doc separator, got:\n%s", s)
	}
}

func TestRenderPackBundleRejectsEmpty(t *testing.T) {
	if _, err := RenderPackBundle(&types.PolicyPack{Manifests: json.RawMessage(`[]`)}); err == nil {
		t.Fatal("expected error for empty manifests")
	}
	if _, err := RenderPackBundle(&types.PolicyPack{Manifests: json.RawMessage(`{"not":"array"}`)}); err == nil {
		t.Fatal("expected error for non-array manifests")
	}
}
