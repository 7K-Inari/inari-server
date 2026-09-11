package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/types"
)

// itItemView builds a template-source catalog item view for unit tests.
func itItemView(id, name string) *catalog.ItemView {
	return &catalog.ItemView{CatalogItem: types.CatalogItem{
		ID: id, Name: name, Source: types.CatalogSourceTemplate,
	}}
}

// stubCatalog is an in-memory TemplateCatalog for DB-free service tests.
type stubCatalog struct {
	items     []catalog.ItemView
	versions  map[string]*types.CatalogItemVersion // itemID+"@"+version
	effective map[string]string                    // orgID+itemID → version
	byID      map[string]*types.CatalogItem
}

func (c *stubCatalog) ListVisible(context.Context, string, string) ([]catalog.ItemView, error) {
	return c.items, nil
}

func (c *stubCatalog) EffectiveVersion(_ context.Context, orgID, itemID, _ string) (string, error) {
	if v, ok := c.effective[orgID+itemID]; ok {
		return v, nil
	}
	return "", errors.New("no version")
}

func (c *stubCatalog) GetVersion(_ context.Context, itemID, version string) (*types.CatalogItemVersion, error) {
	if v, ok := c.versions[itemID+"@"+version]; ok {
		return v, nil
	}
	return nil, errors.New("no such version")
}

func (c *stubCatalog) GetItemByID(_ context.Context, itemID string) (*types.CatalogItem, error) {
	if it, ok := c.byID[itemID]; ok {
		return it, nil
	}
	return nil, errors.New("no such item")
}

func newStubCatalog() *stubCatalog {
	goSvc := *itItemView("template:go-service", "go-service")
	goSvc.DisplayName = "Go Service"
	goSvc.Description = "Minimal Go HTTP service"
	webApp := *itItemView("template:web-app", "web-app")
	capability := catalog.ItemView{CatalogItem: types.CatalogItem{
		ID: "cap:postgres", Name: "postgres", Source: types.CatalogSourceDiscovered,
	}}
	return &stubCatalog{
		items: []catalog.ItemView{goSvc, webApp, capability},
		versions: map[string]*types.CatalogItemVersion{
			"template:go-service@1.0.0": {
				ID: "v1", ItemID: "template:go-service", Version: "1.0.0",
				Schema:  json.RawMessage(testSchema),
				UIHints: json.RawMessage(`{"ui:order":["name","replicas"]}`),
				Payload: json.RawMessage(`{"manifest":{"tags":["go"]}}`),
			},
			"template:web-app@0.3.0": {ID: "v2", ItemID: "template:web-app", Version: "0.3.0"},
		},
		effective: map[string]string{
			"org:acmetemplate:go-service": "1.0.0",
			"org:acmetemplate:web-app":    "0.3.0",
		},
		byID: map[string]*types.CatalogItem{
			"template:go-service": &goSvc.CatalogItem,
			"template:web-app":    &webApp.CatalogItem,
		},
	}
}

func TestListTemplatesFiltersSourceAndResolvesVersions(t *testing.T) {
	svc := NewService(nil, NewStore(), nil, newStubCatalog(), Config{}, nil)
	templates, err := svc.ListTemplates(context.Background(), "org:acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(templates) != 2 {
		t.Fatalf("want 2 templates (discovered capability filtered out), got %d: %+v", len(templates), templates)
	}
	if templates[0].Name != "go-service" || templates[0].Version != "1.0.0" {
		t.Fatalf("unexpected first template: %+v", templates[0])
	}
	if len(templates[0].Tags) != 1 || templates[0].Tags[0] != "go" {
		t.Fatalf("want tags from manifest payload, got %v", templates[0].Tags)
	}
}

func TestGetTemplateReturnsSchemaAndUISchema(t *testing.T) {
	svc := NewService(nil, NewStore(), nil, newStubCatalog(), Config{}, nil)
	tpl, err := svc.GetTemplate(context.Background(), "org:acme", "go-service")
	if err != nil {
		t.Fatal(err)
	}
	if tpl.Version != "1.0.0" || len(tpl.Schema) == 0 || len(tpl.UISchema) == 0 {
		t.Fatalf("want version + schema + uiSchema, got %+v", tpl)
	}
}

func TestGetTemplateNotFound(t *testing.T) {
	svc := NewService(nil, NewStore(), nil, newStubCatalog(), Config{}, nil)
	if _, err := svc.GetTemplate(context.Background(), "org:acme", "nope"); !errors.Is(err, ErrTemplateNotFound) {
		t.Fatalf("want ErrTemplateNotFound, got %v", err)
	}
	// Non-template catalog items must not resolve as templates.
	if _, err := svc.GetTemplate(context.Background(), "org:acme", "postgres"); !errors.Is(err, ErrTemplateNotFound) {
		t.Fatalf("want ErrTemplateNotFound for non-template item, got %v", err)
	}
}

func TestIdempotencyKeyDeterministic(t *testing.T) {
	values := json.RawMessage(`{"name":"payments-api","replicas":2}`)
	k1 := idempotencyKey("org:acme", "go-service", "1.0.0", values)
	k2 := idempotencyKey("org:acme", "go-service", "1.0.0", values)
	if k1 != k2 {
		t.Fatalf("same inputs must produce the same key: %q vs %q", k1, k2)
	}
	if len(k1) != 64 {
		t.Fatalf("key must be a hex sha256, got %q", k1)
	}
}

func TestIdempotencyKeyCanonicalValues(t *testing.T) {
	// encoding/json marshals maps with sorted keys, so key order in the
	// submitted JSON must not change the derived key.
	a := idempotencyKey("org:acme", "go-service", "1.0.0", json.RawMessage(`{"name":"x","replicas":2}`))
	b := idempotencyKey("org:acme", "go-service", "1.0.0", json.RawMessage(`{"replicas":2,"name":"x"}`))
	if a != b {
		t.Fatalf("canonically equal values must produce the same key: %q vs %q", a, b)
	}
}

func TestIdempotencyKeyVariesByInput(t *testing.T) {
	base := idempotencyKey("org:acme", "go-service", "1.0.0", json.RawMessage(`{"name":"x"}`))
	cases := map[string]string{
		"other org":      idempotencyKey("org:other", "go-service", "1.0.0", json.RawMessage(`{"name":"x"}`)),
		"other template": idempotencyKey("org:acme", "node-service", "1.0.0", json.RawMessage(`{"name":"x"}`)),
		"other version":  idempotencyKey("org:acme", "go-service", "2.0.0", json.RawMessage(`{"name":"x"}`)),
		"other values":   idempotencyKey("org:acme", "go-service", "1.0.0", json.RawMessage(`{"name":"y"}`)),
	}
	for name, key := range cases {
		if key == base {
			t.Fatalf("%s must change the key", name)
		}
	}
}

const testSchema = `{
  "type": "object",
  "required": ["name", "replicas"],
  "properties": {
    "name": {"type": "string", "minLength": 3},
    "replicas": {"type": "integer", "minimum": 1},
    "port": {"type": "integer"}
  },
  "additionalProperties": false
}`

func TestValidateValues(t *testing.T) {
	cases := []struct {
		name       string
		schema     string
		values     string
		wantFields int // 0 = valid; >0 = ValidationError with this many leaf errors
	}{
		{"valid", testSchema, `{"name":"payments-api","replicas":2}`, 0},
		{"empty schema accepts", "", `{"anything":true}`, 0},
		{"missing required", testSchema, `{"name":"payments-api"}`, 1},
		// jsonschema/v6 groups all missing required properties of one
		// object into a single leaf error.
		{"missing both required", testSchema, `{}`, 1},
		{"wrong type", testSchema, `{"name":"payments-api","replicas":"two"}`, 1},
		{"too short", testSchema, `{"name":"x","replicas":1}`, 1},
		{"below minimum", testSchema, `{"name":"payments-api","replicas":0}`, 1},
		{"additional property", testSchema, `{"name":"payments-api","replicas":1,"bogus":true}`, 1},
		{"not json", testSchema, `{`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateValues(json.RawMessage(tc.schema), json.RawMessage(tc.values))
			if tc.wantFields == 0 {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			var valErr *ValidationError
			if !errors.As(err, &valErr) {
				t.Fatalf("want *ValidationError, got %T: %v", err, err)
			}
			if len(valErr.Fields) != tc.wantFields {
				t.Fatalf("want %d field errors, got %d: %+v", tc.wantFields, len(valErr.Fields), valErr.Fields)
			}
		})
	}
}

func TestValidateValuesInvalidSchemaIsServerError(t *testing.T) {
	err := validateValues(json.RawMessage(`{"type": 42}`), json.RawMessage(`{}`))
	var valErr *ValidationError
	if errors.As(err, &valErr) {
		t.Fatalf("schema compile faults must not surface as ValidationError, got %v", err)
	}
	if err == nil {
		t.Fatal("want error for uncompilable schema")
	}
}

func TestParseTags(t *testing.T) {
	tags := parseTags(json.RawMessage(`{"manifest":{"name":"go-service","tags":["go","service"]},"skeletonDigest":"sha256:x"}`))
	if len(tags) != 2 || tags[0] != "go" {
		t.Fatalf("want [go service], got %v", tags)
	}
	if tags := parseTags(json.RawMessage(`{}`)); tags != nil {
		t.Fatalf("want nil for missing manifest, got %v", tags)
	}
	if tags := parseTags(nil); tags != nil {
		t.Fatalf("want nil for empty payload, got %v", tags)
	}
}

func TestDefaultDisplayName(t *testing.T) {
	it := itItemView("template:go-service", "go-service")
	if got := defaultDisplayName(it, json.RawMessage(`{"name":"payments-api"}`)); got != "payments-api" {
		t.Fatalf("want wizard name, got %q", got)
	}
	if got := defaultDisplayName(it, json.RawMessage(`{}`)); got != "go-service" {
		t.Fatalf("want template name fallback, got %q", got)
	}
}
