package renderer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/types"
)

// helmHandler renders a direct upstream chart (platform addons like
// cert-manager): the Application pairs the upstream helm
// repo/chart/targetRevision with a git-managed values file via ArgoCD
// multi-source ($values ref) — clean diff history for values edits. In
// applicationset mode a per-cluster overlay value file is layered on top.
type helmHandler struct{}

func (helmHandler) Render(_ context.Context, desc types.SourceDescriptor, p RenderParams) ([]RenderedFile, error) {
	h := desc.Helm
	if h.RepoURL == "" {
		return nil, errors.New("renderer: helm source requires repoUrl")
	}
	if h.Chart == "" {
		return nil, errors.New("renderer: helm source requires chart")
	}
	if h.Version == "" {
		return nil, errors.New("renderer: helm source requires version")
	}
	values, err := valuesYAML(p.Values)
	if err != nil {
		return nil, err
	}

	helmBlock := map[string]any{
		"releaseName": p.Name,
		"valueFiles":  []any{baseValueFile(p)},
	}
	if p.DeployMode == types.AddonDeployModeApplicationSet {
		// Per-cluster overlay (clusters/<cluster>/<name>/values.yaml);
		// clusters without an overlay still render.
		helmBlock["valueFiles"] = []any{baseValueFile(p), overlayValueFile(p)}
		helmBlock["ignoreMissingValueFiles"] = true
	}
	sources := []any{
		map[string]any{
			"repoURL":        h.RepoURL,
			"chart":          h.Chart,
			"targetRevision": h.Version,
			"helm":           helmBlock,
		},
		valuesRefSource(p),
	}
	sourceBlock := map[string]any{"sources": sources}

	files := []RenderedFile{{Path: p.Path + "/values.yaml", Content: values}}
	if p.DeployMode == types.AddonDeployModeApplicationSet {
		files = append(files, RenderedFile{Path: p.Path + "/applicationset.yaml", Content: buildApplicationSet(p, sourceBlock)})
	} else {
		files = append(files, RenderedFile{Path: p.Path + "/application.yaml", Content: buildApplication(p, sourceBlock)})
	}
	return files, nil
}

// valuesYAML converts the JSON values object to YAML; empty renders as an
// empty map so the values file always exists (multi-source requires it).
func valuesYAML(raw json.RawMessage) ([]byte, error) {
	var v map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("renderer: parse helm values: %w", err)
		}
	}
	if v == nil {
		v = map[string]any{}
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("renderer: marshal helm values: %w", err)
	}
	return out, nil
}
