//go:build e2e

// API schema-conformance e2e: with a Keycloak user token (password grant,
// client inari-server), assert GET 200 + schema-valid bodies for the
// console's read endpoints:
//
//	/api/v1/tenants
//	/api/v1/me/permissions
//	/api/v1/tenants/{org}/secret-stores
//	/api/v1/tenants/{org}/audit
//	/api/v1/tenants/{org}/notification-endpoints
//	/api/v1/tenants/{org}/extensions
//	/api/v1/tenants/{org}/templates
//	/api/v1/tenants/{org}/clusters
//
// Response bodies are validated against the huma-generated OpenAPI
// components in dist/openapi.yaml (200-response $ref per operation), so the
// test tracks the spec automatically — including nullable list fields such
// as ListOutputBody4.stores. Run `make export-openapi` first if the spec is
// stale.
//
// Config via env:
//
//	E2E_BASE_URL        server base URL, e.g. http://localhost:8080 (required; test skips if unset)
//	E2E_KEYCLOAK_URL    Keycloak base URL, e.g. http://localhost:8081 (required)
//	E2E_KEYCLOAK_REALM  realm (default inari)
//	E2E_CLIENT_ID       token client (default inari-server)
//	E2E_USERNAME        user (default dev-admin)
//	E2E_PASSWORD        password (default dev-admin)
//	E2E_ORG             tenant slug (default: first entry of /api/v1/tenants)
//	E2E_OPENAPI         path to openapi.yaml (default ../dist/openapi.yaml)
package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	sigsyaml "sigs.k8s.io/yaml"
)

type openapiDoc struct {
	Paths map[string]struct {
		Get *struct {
			Responses map[string]struct {
				Content map[string]struct {
					Schema struct {
						Ref string `json:"$ref"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"get"`
	} `json:"paths"`
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func userToken(t *testing.T) string {
	t.Helper()
	kc := strings.TrimSuffix(os.Getenv("E2E_KEYCLOAK_URL"), "/")
	if kc == "" {
		t.Skip("E2E_KEYCLOAK_URL unset")
	}
	realm := getenv("E2E_KEYCLOAK_REALM", "inari")
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {getenv("E2E_CLIENT_ID", "inari-server")},
		"username":   {getenv("E2E_USERNAME", "dev-admin")},
		"password":   {getenv("E2E_PASSWORD", "dev-admin")},
		"scope":      {"openid organization:*"},
	}
	resp, err := http.PostForm(kc+"/realms/"+realm+"/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token request: status %d: %s", resp.StatusCode, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("token response has no access_token: %s", body)
	}
	return tok.AccessToken
}

// getJSON performs an authenticated GET and returns the decoded body.
func getJSON(t *testing.T, base, token, path string) any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, resp.StatusCode, body)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("GET %s: invalid JSON: %v", path, err)
	}
	return v
}

// responseSchema compiles the 200-response schema of a GET path from the
// OpenAPI doc, resolving internal component $refs.
func responseSchema(t *testing.T, compiler *jsonschema.Compiler, doc *openapiDoc, specURL, path string) *jsonschema.Schema {
	t.Helper()
	p, ok := doc.Paths[path]
	if !ok || p.Get == nil {
		t.Fatalf("path %s has no GET operation in the OpenAPI spec", path)
	}
	r, ok := p.Get.Responses["200"]
	if !ok {
		t.Fatalf("GET %s has no 200 response in the OpenAPI spec", path)
	}
	c, ok := r.Content["application/json"]
	if !ok || c.Schema.Ref == "" {
		t.Fatalf("GET %s 200 response has no application/json schema $ref", path)
	}
	ref := c.Schema.Ref
	if !strings.HasPrefix(ref, "#/") {
		t.Fatalf("GET %s: non-local $ref %q unsupported", path, ref)
	}
	sch, err := compiler.Compile(specURL + ref)
	if err != nil {
		t.Fatalf("compile schema for GET %s (%s): %v", path, ref, err)
	}
	return sch
}

func TestAPISchemaConformance(t *testing.T) {
	base := strings.TrimSuffix(os.Getenv("E2E_BASE_URL"), "/")
	if base == "" {
		t.Skip("E2E_BASE_URL unset; skipping live API e2e")
	}
	token := userToken(t)

	specPath := getenv("E2E_OPENAPI", "../dist/openapi.yaml")
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	specJSON, err := sigsyaml.YAMLToJSON(raw)
	if err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}
	docJSON, err := jsonschema.UnmarshalJSON(bytes.NewReader(specJSON))
	if err != nil {
		t.Fatalf("decode OpenAPI spec: %v", err)
	}
	const specURL = "openapi.json"
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(specURL, docJSON); err != nil {
		t.Fatalf("add OpenAPI resource: %v", err)
	}
	var doc openapiDoc
	if err := json.Unmarshal(specJSON, &doc); err != nil {
		t.Fatalf("decode OpenAPI paths: %v", err)
	}

	type endpoint struct {
		name string
		path string // {org} is substituted below
	}
	endpoints := []endpoint{
		{"list tenants", "/api/v1/tenants"},
		{"my permissions", "/api/v1/me/permissions"},
		{"secret stores", "/api/v1/tenants/{org}/secret-stores"},
		{"audit log", "/api/v1/tenants/{org}/audit"},
		{"notification endpoints", "/api/v1/tenants/{org}/notification-endpoints"},
		{"extensions", "/api/v1/tenants/{org}/extensions"},
		{"templates", "/api/v1/tenants/{org}/templates"},
		{"clusters", "/api/v1/tenants/{org}/clusters"},
	}

	org := os.Getenv("E2E_ORG")
	bodies := map[string]any{}
	for _, ep := range endpoints {
		ep := ep
		t.Run(ep.name, func(t *testing.T) {
			path := ep.path
			if strings.Contains(path, "{org}") {
				if org == "" {
					t.Skip("no tenant slug yet")
				}
				path = strings.ReplaceAll(path, "{org}", url.PathEscape(org))
			}
			sch := responseSchema(t, compiler, &doc, specURL, ep.path)
			body := getJSON(t, base, token, path)
			if err := sch.Validate(body); err != nil {
				t.Fatalf("GET %s: body does not conform to %s: %v", path, sch.Location, err)
			}
			bodies[ep.path] = body
		})
		if ep.path == "/api/v1/tenants" && org == "" {
			// Derive the tenant slug for the per-tenant checks from the
			// tenant switcher list.
			tenants, _ := bodies[ep.path].(map[string]any)["tenants"].([]any)
			for _, it := range tenants {
				if m, ok := it.(map[string]any); ok {
					if slug, ok := m["slug"].(string); ok && slug != "" {
						org = slug
						break
					}
				}
			}
			if org == "" {
				t.Fatal("no tenant returned by /api/v1/tenants; set E2E_ORG")
			}
			t.Logf("using tenant %q for per-tenant endpoints", org)
		}
	}
}
