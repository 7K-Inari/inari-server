package renderer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/types"
)

// kroHandler renders stacked composites: the KRO instance manifest is
// materialized into the repo and the Application source is the git path
// (the orchestrator's render.go behavior, migrated and generalized to both
// deploy modes).
type kroHandler struct {
	resolve ResolveRGDFunc
}

func (h *kroHandler) Render(ctx context.Context, desc types.SourceDescriptor, p RenderParams) ([]RenderedFile, error) {
	if h.resolve == nil {
		return nil, errors.New("renderer: kro handler has no RGD resolver configured")
	}
	rgd, err := h.resolve(ctx, desc.KRO.RGDRef)
	if err != nil {
		return nil, fmt.Errorf("renderer: resolve RGD %q: %w", desc.KRO.RGDRef, err)
	}
	manifest, err := RenderKROInstance(rgd, p.Name, p.namespace(), desc.KRO.Instance)
	if err != nil {
		return nil, err
	}
	files := []RenderedFile{{Path: p.Path + "/instance.yaml", Content: manifest}}
	if p.DeployMode == types.AddonDeployModeApplicationSet {
		files = append(files, RenderedFile{
			Path:    p.Path + "/applicationset.yaml",
			Content: buildApplicationSet(p, map[string]any{"source": gitSource(p, p.Path)}),
		})
	} else {
		files = append(files, RenderedFile{
			Path:    p.Path + "/application.yaml",
			Content: buildApplication(p, map[string]any{"source": gitSource(p, p.Path)}),
		})
	}
	return files, nil
}

// rgdDocument extracts the generated CRD coordinates from an RGD.
type rgdDocument struct {
	Spec struct {
		Schema struct {
			APIVersion string `yaml:"apiVersion"`
			Kind       string `yaml:"kind"`
		} `yaml:"schema"`
	} `yaml:"spec"`
}

// RenderKROInstance renders a deploy spec into a KRO instance manifest:
// apiVersion/kind come from the RGD's generated CRD (kro.run/<apiVersion>,
// schema.kind), metadata from the request, spec from the user form.
// Migrated from orchestrator.RenderInstanceManifest; exported so the
// back-compat wrapper can delegate.
func RenderKROInstance(rgdYAML []byte, name, namespace string, spec json.RawMessage) ([]byte, error) {
	var rgd rgdDocument
	if err := yaml.Unmarshal(rgdYAML, &rgd); err != nil {
		return nil, fmt.Errorf("renderer: parse RGD: %w", err)
	}
	if rgd.Spec.Schema.Kind == "" {
		return nil, errors.New("renderer: RGD has no spec.schema.kind")
	}
	var specMap map[string]any
	if len(spec) > 0 {
		if err := json.Unmarshal(spec, &specMap); err != nil {
			return nil, fmt.Errorf("renderer: parse spec: %w", err)
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
