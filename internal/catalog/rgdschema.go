package catalog

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// rgdDocument mirrors the subset of a KRO ResourceGraphDefinition that
// carries the instance schema (spec.schema).
type rgdDocument struct {
	Spec struct {
		Schema map[string]any `yaml:"schema"`
	} `yaml:"spec"`
}

// schemaFromRGD extracts an OpenAPI-v3-flavoured JSON schema from a KRO
// ResourceGraphDefinition's spec.schema section. Catalog packages ship the
// RGD but no schema.json layer, so without this every catalog item preview
// and deploy form renders empty (live incident 2026-09-16).
//
// KRO simple-schema scalar syntax: `string | required=true default="x"`.
// Nested maps become object properties; the apiVersion/kind/status keys are
// dropped (not user-configurable inputs).
func schemaFromRGD(rgd []byte) (json.RawMessage, error) {
	var doc rgdDocument
	if err := yaml.Unmarshal(rgd, &doc); err != nil {
		return nil, fmt.Errorf("catalog: parse rgd schema: %w", err)
	}
	spec, _ := doc.Spec.Schema["spec"].(map[string]any)
	if len(spec) == 0 {
		return nil, nil
	}
	props, required := simpleSchemaProps(spec)
	out := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		sort.Strings(required)
		out["required"] = required
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

// simpleSchemaProps converts one simple-schema level into JSON-schema
// properties plus the names marked required.
func simpleSchemaProps(in map[string]any) (map[string]any, []string) {
	props := make(map[string]any, len(in))
	var required []string
	for name, raw := range in {
		switch v := raw.(type) {
		case string:
			prop, req := parseSimpleScalar(v)
			props[name] = prop
			if req {
				required = append(required, name)
			}
		case map[string]any:
			sub, subReq := simpleSchemaProps(v)
			obj := map[string]any{"type": "object", "properties": sub}
			if len(subReq) > 0 {
				sort.Strings(subReq)
				obj["required"] = subReq
			}
			props[name] = obj
		default:
			props[name] = map[string]any{}
		}
	}
	return props, required
}

// parseSimpleScalar parses `integer | required=true default=2` into a JSON
// schema fragment and whether the field is required.
func parseSimpleScalar(decl string) (map[string]any, bool) {
	parts := strings.SplitN(decl, "|", 2)
	prop := map[string]any{"type": strings.TrimSpace(parts[0])}
	required := false
	if len(parts) == 2 {
		for _, mod := range strings.Fields(parts[1]) {
			k, v, ok := strings.Cut(mod, "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "required":
				required = v == "true"
			case "default":
				prop["default"] = coerceScalar(prop["type"].(string), v)
			case "description":
				prop["description"] = v
			case "enum":
				prop["enum"] = strings.Split(v, ",")
			}
		}
	}
	return prop, required
}

// coerceScalar renders default values with the declared JSON type.
func coerceScalar(typ, v string) any {
	switch typ {
	case "integer":
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	case "number", "float":
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
	case "boolean":
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return v
}
