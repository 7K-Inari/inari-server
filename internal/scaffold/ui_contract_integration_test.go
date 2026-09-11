//go:build integration

// UI-contract tests (M8.W5): the inari-ui /templates wizard client
// (inari-ui/src/api/templates.ts) is hand-written and must not change, so
// these tests pin the exact JSON shapes the server exposes to it:
//
//	POST /api/v1/tenants/{org}/scaffolds      {templateId,name,parameters} → 201 {scaffold}
//	GET  /api/v1/tenants/{org}/scaffolds/{id} → {scaffold: ScaffoldRun}
//
// ScaffoldRun = {id, templateId, templateName, name, tenant, phase,
// message, outputs{repoUrl,pipelineUrl,catalogItemId}, createdAt}.
package scaffold

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// uiScaffold mirrors the UI client's ScaffoldRun interface field-for-field.
type uiScaffold struct {
	ID           string  `json:"id"`
	TemplateID   string  `json:"templateId"`
	TemplateName string  `json:"templateName"`
	Name         string  `json:"name"`
	Tenant       string  `json:"tenant"`
	Phase        string  `json:"phase"`
	Message      *string `json:"message"`
	Outputs      struct {
		RepoURL       *string `json:"repoUrl"`
		PipelineURL   *string `json:"pipelineUrl"`
		CatalogItemID *string `json:"catalogItemId"`
	} `json:"outputs"`
	CreatedAt string `json:"createdAt"`
}

func decodeScaffold(t *testing.T, body string) uiScaffold {
	t.Helper()
	var env struct {
		Schema   string     `json:"$schema"` // huma OpenAPI schema link; the UI client ignores it
		Scaffold uiScaffold `json:"scaffold"`
	}
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("scaffold envelope must match the UI ScaffoldRun shape exactly: %v\n%s", err, body)
	}
	return env.Scaffold
}

func TestUIScaffoldContract(t *testing.T) {
	f := newITFixture(t)

	// Create via the UI contract: {templateId, name, parameters} → 201 {scaffold}.
	code, body := f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "good",
		`{"templateId":"template:go-service","name":"payments-api","parameters":{"name":"payments-api","replicas":2}}`)
	if code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", code, body)
	}
	sc := decodeScaffold(t, body)
	if sc.ID == "" || sc.TemplateID != "template:go-service" || sc.TemplateName != "go-service" ||
		sc.Name != "payments-api" || sc.Tenant != "acme" || sc.Phase != "pending" ||
		sc.Message != nil || sc.CreatedAt == "" {
		t.Fatalf("create contract mismatch: %+v", sc)
	}
	if sc.Outputs.RepoURL != nil || sc.Outputs.PipelineURL != nil || sc.Outputs.CatalogItemID != nil {
		t.Fatalf("fresh run outputs must be nulls, got %+v", sc.Outputs)
	}

	// Idempotent replay → 200 with the same run id.
	code, body = f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "good",
		`{"templateId":"template:go-service","name":"payments-api","parameters":{"name":"payments-api","replicas":2}}`)
	if code != http.StatusOK {
		t.Fatalf("want 200 on replay, got %d: %s", code, body)
	}
	if again := decodeScaffold(t, body); again.ID != sc.ID {
		t.Fatalf("replay must return the same run id: %+v", again)
	}

	// Poll → same contract shape.
	code, body = f.req(t, "GET", "/api/v1/tenants/acme/scaffolds/"+sc.ID, "good", "")
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	if polled := decodeScaffold(t, body); polled.ID != sc.ID || polled.Phase != "pending" {
		t.Fatalf("poll contract mismatch: %+v", polled)
	}

	// Unknown run → 404; cross-org → 404.
	if code, _ := f.req(t, "GET", "/api/v1/tenants/acme/scaffolds/run:nope", "good", ""); code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown run, got %d", code)
	}
	if code, _ := f.req(t, "GET", "/api/v1/tenants/other/scaffolds/"+sc.ID, "other", ""); code != http.StatusNotFound {
		t.Fatalf("want 404 for foreign run, got %d", code)
	}

	// Unknown template → 404.
	if code, _ := f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "good",
		`{"templateId":"template:nope","name":"x","parameters":{"name":"payments-api"}}`); code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown template, got %d", code)
	}

	// Schema-violating parameters → 422 before any run row exists.
	before := countRuns(t, f)
	code, body = f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "good",
		`{"templateId":"template:go-service","name":"bad","parameters":{"name":"x","bogus":1}}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d: %s", code, body)
	}
	if countRuns(t, f) != before {
		t.Fatalf("422 must not create a run row")
	}

	// Authz: non-member → 403; developer denied → create forbidden, read ok.
	if code, _ := f.req(t, "GET", "/api/v1/tenants/acme/scaffolds/"+sc.ID, "other", ""); code != http.StatusForbidden {
		t.Fatalf("want 403 for non-member, got %d", code)
	}
	f.az.deny["developer"] = true
	if code, _ := f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "good",
		`{"templateId":"template:go-service","name":"orders-api","parameters":{"name":"orders-api"}}`); code != http.StatusForbidden {
		t.Fatalf("want 403 when developer denied, got %d", code)
	}
	if code, _ := f.req(t, "GET", "/api/v1/tenants/acme/scaffolds/"+sc.ID, "good", ""); code != http.StatusOK {
		t.Fatalf("want 200 for viewer read, got %d", code)
	}
	f.az.deny["developer"] = false
}

func countRuns(t *testing.T, f *itFixture) int {
	t.Helper()
	var n int
	if err := f.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM scaffold_runs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestUIFullRunContract drives a run end-to-end through the UI surface:
// list → detail → create → poll until completed with all outputs populated.
func TestUIFullRunContract(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{
		"deploy/app.yaml.tmpl": "name: {{ .Values.name }}\nns: {{ .Tenant.Namespace }}\n",
	})
	git := gitprovider.NewFake()
	reg := &fakeRegistrar{}
	up := &fakeUpserter{}
	rbac := &fakeRBACBinder{}
	f.svc.WithExecEnv(&ExecEnv{
		Git: git, GitOrg: "acme-platform", Registrar: reg, Upsert: up, RBAC: rbac,
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(),
	})

	// List templates: TemplateSummary keys exactly as the UI client declares.
	code, body := f.req(t, "GET", "/api/v1/tenants/acme/templates", "good", "")
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	var list struct {
		Schema    string `json:"$schema"` // huma OpenAPI schema link; ignored by the UI client
		Templates []struct {
			ID          string   `json:"id"`
			Name        string   `json:"name"`
			DisplayName string   `json:"displayName"`
			Description string   `json:"description"`
			Tags        []string `json:"tags"`
			Version     string   `json:"version"`
		} `json:"templates"`
	}
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil {
		t.Fatalf("template list must match TemplateSummary exactly: %v\n%s", err, body)
	}
	if len(list.Templates) != 1 || list.Templates[0].ID != "template:go-service" {
		t.Fatalf("unexpected list: %s", body)
	}

	// Detail: TemplateDetail adds schema + uiSchema (RJSF wizard inputs).
	code, body = f.req(t, "GET", "/api/v1/tenants/acme/templates/template:go-service", "good", "")
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	var detail struct {
		Template struct {
			ID       string          `json:"id"`
			Schema   json.RawMessage `json:"schema"`
			UISchema json.RawMessage `json:"uiSchema"`
		} `json:"template"`
	}
	if err := json.Unmarshal([]byte(body), &detail); err != nil {
		t.Fatal(err)
	}
	var schemaObj, uiObj map[string]any
	if json.Unmarshal(detail.Template.Schema, &schemaObj) != nil || len(schemaObj) == 0 {
		t.Fatalf("schema must be a JSON object for RJSF: %s", detail.Template.Schema)
	}
	if json.Unmarshal(detail.Template.UISchema, &uiObj) != nil || len(uiObj) == 0 {
		t.Fatalf("uiSchema must be a JSON object for RJSF: %s", detail.Template.UISchema)
	}

	// Create + drive the reconcile loop until terminal.
	code, body = f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "good",
		`{"templateId":"template:go-service","name":"payments-api","parameters":{"name":"payments-api"}}`)
	if code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", code, body)
	}
	sc := decodeScaffold(t, body)
	for range 10 {
		f.svc.reconcileOnce(ctx, time.Millisecond)
		run, _, err := f.svc.GetRun(ctx, "org:acme", sc.ID)
		if err != nil {
			t.Fatal(err)
		}
		if run.Phase == types.ScaffoldPhaseCompleted || run.Phase == types.ScaffoldPhaseFailed {
			break
		}
	}

	code, body = f.req(t, "GET", "/api/v1/tenants/acme/scaffolds/"+sc.ID, "good", "")
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	done := decodeScaffold(t, body)
	if done.Phase != "completed" {
		t.Fatalf("phase = %q, want completed (message=%v)", done.Phase, done.Message)
	}
	if done.Message != nil {
		t.Fatalf("successful run must have null message, got %q", *done.Message)
	}
	if done.Outputs.RepoURL == nil || !strings.Contains(*done.Outputs.RepoURL, "acme-payments-api") {
		t.Fatalf("repoUrl missing: %+v", done.Outputs)
	}
	if done.Outputs.PipelineURL == nil || *done.Outputs.PipelineURL == "" {
		t.Fatalf("pipelineUrl missing: %+v", done.Outputs)
	}
	if done.Outputs.CatalogItemID == nil || *done.Outputs.CatalogItemID != "component:acme--payments-api" {
		t.Fatalf("catalogItemId missing: %+v", done.Outputs)
	}
}
