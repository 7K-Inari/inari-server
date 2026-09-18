package catalog

import (
	"encoding/json"
	"testing"
)

func TestSchemaFromRGD(t *testing.T) {
	rgd := []byte(`apiVersion: kro.run/v1alpha1
kind: ResourceGraphDefinition
metadata:
  name: web-service
spec:
  schema:
    apiVersion: v1alpha1
    kind: WebService
    spec:
      name: string | required=true
      namespace: string | default="default"
      replicas: integer | default=2
      tls: boolean | default=true
      host: string | required=true
    status:
      url: string
  resources: []
`)
	raw, err := schemaFromRGD(rgd)
	if err != nil {
		t.Fatalf("schemaFromRGD: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["type"] != "object" {
		t.Fatalf("type = %v", doc["type"])
	}
	props := doc["properties"].(map[string]any)
	if len(props) != 5 {
		t.Fatalf("properties = %d, want 5 (status must be excluded): %v", len(props), props)
	}
	if props["replicas"].(map[string]any)["default"] != int64(2) && props["replicas"].(map[string]any)["default"] != float64(2) {
		t.Fatalf("replicas default = %#v", props["replicas"].(map[string]any)["default"])
	}
	if props["tls"].(map[string]any)["default"] != true {
		t.Fatalf("tls default = %#v", props["tls"].(map[string]any)["default"])
	}
	req := doc["required"].([]any)
	if len(req) != 2 || req[0] != "host" || req[1] != "name" {
		t.Fatalf("required = %v", req)
	}
}

func TestSchemaFromRGDNoSpec(t *testing.T) {
	raw, err := schemaFromRGD([]byte("apiVersion: kro.run/v1alpha1\nspec: {}\n"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if raw != nil {
		t.Fatalf("expected nil schema, got %s", raw)
	}
}
