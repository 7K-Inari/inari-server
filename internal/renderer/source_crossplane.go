package renderer

import (
	"context"
	"errors"

	"github.com/7K-Inari/inari-server/internal/types"
)

// xpHandler renders Crossplane managed resources / claims: the claim or
// managed-resource YAML is materialized into the repo (same mechanics as
// the manifests kind — Crossplane resources are plain YAML to git) plus an
// Application/ApplicationSet sourced at that directory. The kind stays
// distinct so callers can express intent (self-service claims vs. plain
// manifests) and so XP-specific validation can grow here without touching
// the manifests path.
type xpHandler struct{}

func (xpHandler) Render(_ context.Context, desc types.SourceDescriptor, p RenderParams) ([]RenderedFile, error) {
	docs, err := inlineDocuments(desc.Crossplane.Manifests)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, errors.New("renderer: crossplane source has no manifests")
	}

	files := make([]RenderedFile, 0, len(docs)+1)
	for i, doc := range docs {
		name, content, err := renderManifestDoc(i, doc)
		if err != nil {
			return nil, err
		}
		files = append(files, RenderedFile{Path: p.Path + "/manifests/" + name, Content: content})
	}
	sourceBlock := map[string]any{"source": gitSource(p, p.Path+"/manifests")}
	if p.DeployMode == types.AddonDeployModeApplicationSet {
		files = append(files, RenderedFile{Path: p.Path + "/applicationset.yaml", Content: buildApplicationSet(p, sourceBlock)})
	} else {
		files = append(files, RenderedFile{Path: p.Path + "/application.yaml", Content: buildApplication(p, sourceBlock)})
	}
	return files, nil
}
