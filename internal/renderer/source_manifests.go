package renderer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/types"
)

// manifestsHandler materializes plain (optionally parameterized) YAML into
// <path>/manifests/ plus an Application sourced at that directory.
// Parameterization is plain ${key} substitution from ManifestSource.Params
// — deliberately not a templating engine.
type manifestsHandler struct{}

func (manifestsHandler) Render(_ context.Context, desc types.SourceDescriptor, p RenderParams) ([]RenderedFile, error) {
	docs, err := inlineDocuments(desc.Manifests.Inline)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, errors.New("renderer: manifests source has no inline documents")
	}

	files := make([]RenderedFile, 0, len(docs)+1)
	for i, doc := range docs {
		doc = substituteParams(doc, desc.Manifests.Params)
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

// inlineDocuments accepts either a JSON string holding multi-document YAML
// (docs separated by ---) or a JSON array of per-document YAML strings.
func inlineDocuments(raw json.RawMessage) ([]string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	switch trimmed[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("renderer: parse manifests inline: %w", err)
		}
		return splitYAMLDocs(s), nil
	case '[':
		var docs []string
		if err := json.Unmarshal(raw, &docs); err != nil {
			return nil, fmt.Errorf("renderer: parse manifests inline: %w", err)
		}
		return docs, nil
	default:
		return nil, errors.New("renderer: manifests inline must be a JSON string or array of strings")
	}
}

// splitYAMLDocs splits multi-document YAML on --- separators, dropping
// empty documents.
func splitYAMLDocs(multi string) []string {
	var docs []string
	for _, part := range strings.Split(multi, "\n---") {
		part = strings.TrimSpace(strings.TrimPrefix(part, "---"))
		if part != "" {
			docs = append(docs, part)
		}
	}
	return docs
}

// substituteParams replaces ${key} placeholders with params values.
func substituteParams(doc string, params map[string]string) string {
	for k, v := range params {
		doc = strings.ReplaceAll(doc, "${"+k+"}", v)
	}
	return doc
}

// manifestMeta is the validation view of one manifest document.
type manifestMeta struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
}

// renderManifestDoc validates one document and emits it under a
// deterministic, ordering-stable file name: NN-<kind>-<name>.yaml.
func renderManifestDoc(index int, doc string) (string, []byte, error) {
	var meta manifestMeta
	if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
		return "", nil, fmt.Errorf("renderer: manifests doc %d: parse: %w", index, err)
	}
	if meta.Kind == "" {
		return "", nil, fmt.Errorf("renderer: manifests doc %d: missing kind", index)
	}
	if meta.Metadata.Name == "" {
		return "", nil, fmt.Errorf("renderer: manifests doc %d: missing metadata.name", index)
	}
	name := fmt.Sprintf("%02d-%s-%s.yaml", index,
		strings.ToLower(meta.Kind), strings.ToLower(meta.Metadata.Name))
	return name, []byte(strings.TrimRight(doc, "\n") + "\n"), nil
}
