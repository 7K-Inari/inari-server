package orchestrator

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/types"
)

// RepoPath is the deterministic location of an instance's manifests in the
// tenant state repo: clusters/<cluster>/<item>/<instance>/.
func RepoPath(clusterID, itemID, instanceID string) string {
	return fmt.Sprintf("clusters/%s/%s/%s", clusterID, strings.TrimPrefix(itemID, "curated:"), instanceID)
}

type rgdDocument struct {
	Spec struct {
		Schema struct {
			APIVersion string `yaml:"apiVersion"`
			Kind       string `yaml:"kind"`
		} `yaml:"schema"`
	} `yaml:"spec"`
}

// RenderInstanceManifest renders a deploy spec into a KRO instance manifest:
// apiVersion/kind come from the RGD's generated CRD (kro.run/<apiVersion>,
// schema.kind), metadata from the request, spec from the user form.
func RenderInstanceManifest(ver *types.CatalogItemVersion, name, namespace string, spec json.RawMessage) ([]byte, error) {
	var payload struct {
		RGD string `json:"rgd"`
	}
	if err := json.Unmarshal(ver.Payload, &payload); err != nil {
		return nil, fmt.Errorf("orchestrator: parse version payload: %w", err)
	}
	var rgd rgdDocument
	if err := yaml.Unmarshal([]byte(payload.RGD), &rgd); err != nil {
		return nil, fmt.Errorf("orchestrator: parse RGD: %w", err)
	}
	if rgd.Spec.Schema.Kind == "" {
		return nil, fmt.Errorf("orchestrator: RGD has no spec.schema.kind")
	}
	var specMap map[string]any
	if len(spec) > 0 {
		if err := json.Unmarshal(spec, &specMap); err != nil {
			return nil, fmt.Errorf("orchestrator: parse spec: %w", err)
		}
	}
	doc := map[string]any{
		"apiVersion": "kro.run/" + rgd.Spec.Schema.APIVersion,
		"kind":       rgd.Spec.Schema.Kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
		"spec": specMap,
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ApplicationParams describes the ArgoCD Application to render.
type ApplicationParams struct {
	Name           string
	Project        string
	RepoURL        string
	Path           string
	TargetRevision string
	DestNamespace  string
}

// RenderArgoCDApplication renders the tenant-local ArgoCD Application that
// reconciles an instance path in the tenant state repo.
func RenderArgoCDApplication(p ApplicationParams) []byte {
	doc := map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata": map[string]any{
			"name":      p.Name,
			"namespace": "argocd",
		},
		"spec": map[string]any{
			"project": p.Project,
			"source": map[string]any{
				"repoURL":        p.RepoURL,
				"path":           p.Path,
				"targetRevision": p.TargetRevision,
			},
			"destination": map[string]any{
				"server":    "https://kubernetes.default.svc",
				"namespace": p.DestNamespace,
			},
			"syncPolicy": map[string]any{
				"automated": map[string]any{
					"selfHeal": true,
					"prune":    true,
				},
			},
		},
	}
	out, _ := yaml.Marshal(doc)
	return out
}
