package policyservice

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/types"
)

// RenderPackBundle concatenates a pack's manifests (a JSON array of
// documents) into a multi-document YAML bundle.
func RenderPackBundle(pack *types.PolicyPack) ([]byte, error) {
	var docs []json.RawMessage
	if err := json.Unmarshal(pack.Manifests, &docs); err != nil {
		return nil, fmt.Errorf("policyservice: pack manifests must be a JSON array: %w", err)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("policyservice: pack manifests must be a non-empty JSON array")
	}
	var buf bytes.Buffer
	for i, raw := range docs {
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("policyservice: manifest %d: %w", i, err)
		}
		out, err := yaml.Marshal(doc)
		if err != nil {
			return nil, fmt.Errorf("policyservice: manifest %d to yaml: %w", i, err)
		}
		if i > 0 {
			buf.WriteString("---\n")
		}
		buf.Write(out)
	}
	return buf.Bytes(), nil
}
