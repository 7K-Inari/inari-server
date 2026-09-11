//go:build integration

package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type itValidator struct{}

func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "good":
		return &authn.Identity{Subject: "dev-1", Organizations: []string{"acme"}}, nil
	case "other":
		return &authn.Identity{Subject: "dev-2", Organizations: []string{"other"}}, nil
	case "outsider":
		return &authn.Identity{Subject: "dev-3"}, nil
	}
	return nil, errors.New("invalid token")
}

// itAuthorizer denies specific relations, allows everything else.
type itAuthorizer struct{ deny map[string]bool }

func (a itAuthorizer) Check(_ context.Context, _, relation, _ string) (bool, error) {
	return !a.deny[relation], nil
}
func (a itAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type itTenants map[string]*types.Organization

func (t itTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if o, ok := t[slug]; ok {
		return o, nil
	}
	return nil, tenancy.ErrOrgNotFound
}

const itSchema = `{
  "type": "object",
  "required": ["name"],
  "properties": {
    "name": {"type": "string", "minLength": 3},
    "replicas": {"type": "integer", "minimum": 1}
  },
  "additionalProperties": false
}`

type itFixture struct {
	srv    *httptest.Server
	svc    *Service
	db     *db.DB
	az     itAuthorizer
	schema string
}

func newITFixture(t *testing.T) *itFixture {
	t.Helper()
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("inari"),
		postgres.WithUsername("inari"),
		postgres.WithPassword("inari"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
	)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	url, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES
		   ('org:acme','acme','Acme','kc-acme'), ('org:other','other','Other','kc-other');
		 INSERT INTO catalog_items (id, source, name, display_name, description) VALUES
		   ('template:go-service','template','go-service','Go Service','Minimal Go HTTP service')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO catalog_item_versions (item_id, version, channel, schema, ui_hints, payload) VALUES
		   ('template:go-service','1.0.0','stable',$1::jsonb,'{"ui:order":["name"]}','{"manifest":{"tags":["go","service"]}}')`,
		itSchema); err != nil {
		t.Fatal(err)
	}
	auditStore := audit.NewStore()
	catalogSvc := catalog.NewService(database, catalog.NewStore(), nil, auditStore, nil)
	svc := NewService(database, NewStore(), auditStore, catalogSvc, Config{MaxAttempts: 5, GitOrg: "acme-platform"}, slog.Default())
	az := itAuthorizer{deny: map[string]bool{}}
	h := NewHandler(svc, itTenants{
		"acme":  {ID: "org:acme", Slug: "acme"},
		"other": {ID: "org:other", Slug: "other"},
	}, az)
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	h.RegisterRoutes(api)
	return &itFixture{srv: httptest.NewServer(router), svc: svc, db: database, az: az}
}

func (f *itFixture) req(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	r, err := http.NewRequest(method, f.srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// --- Store round-trip ----------------------------------------------------

func TestStoreRoundTrip(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()

	run, steps, existed, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"payments-api","replicas":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if existed {
		t.Fatal("first create must not report replay")
	}
	if run.Phase != types.ScaffoldPhasePending || run.TemplateVersion != "1.0.0" || run.DisplayName != "payments-api" {
		t.Fatalf("unexpected run: %+v", run)
	}
	if len(steps) != len(stepNames) {
		t.Fatalf("want %d initial steps, got %d", len(stepNames), len(steps))
	}

	// GetRun: org-scoped, steps in phase order.
	got, gotSteps, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != run.ID || got.IdempotencyKey == "" {
		t.Fatalf("unexpected fetched run: %+v", got)
	}
	for i, n := range stepNames {
		if gotSteps[i].Name != n || gotSteps[i].State != types.ScaffoldStepPending {
			t.Fatalf("step %d out of order/state: %+v", i, gotSteps[i])
		}
	}
	// Cross-org reads look like absence.
	if _, _, err := f.svc.GetRun(ctx, "org:other", run.ID); !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("want ErrRunNotFound for foreign org, got %v", err)
	}

	// ListRuns.
	runs, err := f.svc.store.ListRuns(ctx, f.db.Pool, "org:acme")
	if err != nil || len(runs) != 1 {
		t.Fatalf("want 1 run, got %v (%v)", runs, err)
	}

	// ClaimNextRunnable returns the pending run inside a tx.
	err = f.db.WithTx(ctx, func(tx pgx.Tx) error {
		claimed, err := f.svc.store.ClaimNextRunnable(ctx, tx)
		if err != nil || claimed == nil || claimed.ID != run.ID {
			return fmt.Errorf("claim: %v (%v)", claimed, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// UpdateStep upserts a transition.
	st := &types.ScaffoldRunStep{RunID: run.ID, Name: "rendering", State: types.ScaffoldStepCompleted, Attempts: 1, MaxAttempts: 5, Result: json.RawMessage(`{"files":3}`)}
	if err := f.svc.store.UpdateStep(ctx, f.db.Pool, st); err != nil {
		t.Fatal(err)
	}
	_, stepsAfter, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stepsAfter[0].State != types.ScaffoldStepCompleted || stepsAfter[0].Attempts != 1 || len(stepsAfter) != len(stepNames) {
		t.Fatalf("step update not persisted: %+v", stepsAfter[0])
	}

	// Phase update; then SetCancelled fails on terminal runs.
	if err := f.svc.store.UpdateRunPhase(ctx, f.db.Pool, run.ID, types.ScaffoldPhaseRendering, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CancelRun(ctx, "dev-1", "org:acme", run.ID); err != nil {
		t.Fatal(err)
	}
	// Cancelled runs are no longer claimable.
	err = f.db.WithTx(ctx, func(tx pgx.Tx) error {
		claimed, err := f.svc.store.ClaimNextRunnable(ctx, tx)
		if claimed != nil || err != nil {
			return fmt.Errorf("cancelled run must not be claimable: %v", claimed)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Second cancel is a no-op.
	if err := f.svc.CancelRun(ctx, "dev-1", "org:acme", run.ID); err != nil {
		t.Fatalf("double cancel must be a no-op, got %v", err)
	}
	// Terminal phase → cancel conflicts.
	if err := f.svc.store.UpdateRunPhase(ctx, f.db.Pool, run.ID, types.ScaffoldPhaseFailed, "boom", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CancelRun(ctx, "dev-1", "org:acme", run.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("want ErrInvalidState cancelling terminal run, got %v", err)
	}
}

// --- Idempotent create ---------------------------------------------------

func TestCreateRunIdempotent(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	values := json.RawMessage(`{"name":"payments-api"}`)

	r1, _, existed1, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", values)
	if err != nil || existed1 {
		t.Fatalf("first create: existed=%v err=%v", existed1, err)
	}
	r2, steps2, existed2, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", values)
	if err != nil {
		t.Fatal(err)
	}
	if !existed2 || r2.ID != r1.ID {
		t.Fatalf("replay must return the existing run %q, got %q (existed=%v)", r1.ID, r2.ID, existed2)
	}
	if len(steps2) != len(stepNames) {
		t.Fatalf("replay must return existing steps, got %d", len(steps2))
	}
	// Exactly one run row exists.
	var n int
	if err := f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM scaffold_runs WHERE org_id='org:acme'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("want exactly 1 run row, got %d (%v)", n, err)
	}
	// Different values derive a different key → a new run.
	r3, _, existed3, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"orders-api"}`))
	if err != nil || existed3 || r3.ID == r1.ID {
		t.Fatalf("different values must create a new run: %q existed=%v err=%v", r3.ID, existed3, err)
	}
	// Outbox + audit were written for each real create.
	var events int
	if err := f.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE event_type=$1`, types.EventScaffoldRunCreated).Scan(&events); err != nil || events != 2 {
		t.Fatalf("want 2 run_created outbox events, got %d (%v)", events, err)
	}
}

// Concurrent identical submits must collapse to one run: losers of the
// unique-index race take the ErrIdempotencyConflict replay path.
func TestCreateRunConcurrentIdempotent(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	values := json.RawMessage(`{"name":"payments-api"}`)

	const n = 8
	ids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", values)
			ids[i], errs[i] = "", err
			if r != nil {
				ids[i] = r.ID
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("concurrent create %d failed: %v", i, errs[i])
		}
		if ids[i] != ids[0] {
			t.Fatalf("concurrent creates diverged: %q vs %q", ids[i], ids[0])
		}
	}
	var count int
	if err := f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM scaffold_runs WHERE org_id='org:acme'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("want exactly 1 run row, got %d (%v)", count, err)
	}
}

// --- HTTP API ------------------------------------------------------------

func TestHTTPAuthz(t *testing.T) {
	f := newITFixture(t)

	// Unauthenticated.
	if code, _ := f.req(t, "GET", "/api/v1/tenants/acme/templates", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", code)
	}
	// Not a member of the org.
	if code, _ := f.req(t, "GET", "/api/v1/tenants/acme/templates", "other", ""); code != http.StatusForbidden {
		t.Fatalf("want 403 for non-member, got %d", code)
	}
	// Unknown org.
	if code, _ := f.req(t, "GET", "/api/v1/tenants/nope/templates", "good", ""); code != http.StatusForbidden {
		// not a member (claim check precedes tenant resolution)
		t.Fatalf("want 403 for unknown org, got %d", code)
	}
	// Authorizer denies developer: reads pass, create is forbidden.
	f.az.deny["developer"] = true
	if code, _ := f.req(t, "GET", "/api/v1/tenants/acme/templates", "good", ""); code != http.StatusOK {
		t.Fatalf("want 200 for viewer-allowed list, got %d", code)
	}
	if code, _ := f.req(t, "POST", "/api/v1/tenants/acme/templates/go-service/runs", "good", `{"values":{"name":"payments-api"}}`); code != http.StatusForbidden {
		t.Fatalf("want 403 when developer denied, got %d", code)
	}
	f.az.deny["developer"] = false
}

func TestHTTPTemplates(t *testing.T) {
	f := newITFixture(t)

	code, body := f.req(t, "GET", "/api/v1/tenants/acme/templates", "good", "")
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	var list struct {
		Templates []TemplateSummary `json:"templates"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Templates) != 1 || list.Templates[0].Name != "go-service" || list.Templates[0].Version != "1.0.0" {
		t.Fatalf("unexpected template list: %s", body)
	}
	if len(list.Templates[0].Tags) != 2 {
		t.Fatalf("want manifest tags, got %v", list.Templates[0].Tags)
	}

	code, body = f.req(t, "GET", "/api/v1/tenants/acme/templates/go-service", "good", "")
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	var detail struct {
		Template TemplateDetail `json:"template"`
	}
	if err := json.Unmarshal([]byte(body), &detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Template.Schema) == 0 || len(detail.Template.UISchema) == 0 {
		t.Fatalf("want schema + uiSchema, got %s", body)
	}

	if code, _ := f.req(t, "GET", "/api/v1/tenants/acme/templates/nope", "good", ""); code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown template, got %d", code)
	}
}

func TestHTTPRunLifecycle(t *testing.T) {
	f := newITFixture(t)

	// 422 on schema violations, before any run row exists.
	code, body := f.req(t, "POST", "/api/v1/tenants/acme/templates/go-service/runs", "good", `{"values":{"name":"x","bogus":1}}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d: %s", code, body)
	}
	var runs int
	if err := f.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM scaffold_runs`).Scan(&runs); err != nil || runs != 0 {
		t.Fatalf("422 must not create a run row (%d rows)", runs)
	}

	// Unknown version → 400.
	if code, _ := f.req(t, "POST", "/api/v1/tenants/acme/templates/go-service/runs", "good", `{"version":"9.9.9","values":{"name":"payments-api"}}`); code != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown version, got %d", code)
	}

	// Valid create → 201 with the UI contract shape.
	code, body = f.req(t, "POST", "/api/v1/tenants/acme/templates/go-service/runs", "good", `{"values":{"name":"payments-api","replicas":2}}`)
	if code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", code, body)
	}
	var created struct {
		Run struct {
			ID           string          `json:"id"`
			TemplateName string          `json:"templateName"`
			Version      string          `json:"version"`
			DisplayName  string          `json:"displayName"`
			Phase        string          `json:"phase"`
			Steps        []stepView      `json:"steps"`
			Outputs      json.RawMessage `json:"outputs"`
			CreatedBy    string          `json:"createdBy"`
		} `json:"run"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	r := created.Run
	if r.ID == "" || r.TemplateName != "go-service" || r.Version != "1.0.0" ||
		r.DisplayName != "payments-api" || r.Phase != "pending" || r.CreatedBy != "dev-1" {
		t.Fatalf("contract mismatch: %s", body)
	}
	if len(r.Steps) != len(stepNames) || r.Steps[0].Name != "rendering" || r.Steps[0].State != "pending" {
		t.Fatalf("steps contract mismatch: %s", body)
	}

	// Idempotent replay → 200 with the same run id.
	code, body = f.req(t, "POST", "/api/v1/tenants/acme/templates/go-service/runs", "good", `{"values":{"name":"payments-api","replicas":2}}`)
	if code != http.StatusOK {
		t.Fatalf("want 200 on replay, got %d: %s", code, body)
	}
	if !strings.Contains(body, `"id":"`+r.ID+`"`) {
		t.Fatalf("replay must return the same run id: %s", body)
	}

	// Poll → same contract.
	code, body = f.req(t, "GET", "/api/v1/tenants/acme/scaffold-runs/"+r.ID, "good", "")
	if code != http.StatusOK || !strings.Contains(body, `"templateName":"go-service"`) {
		t.Fatalf("want 200 with contract, got %d: %s", code, body)
	}
	// Cross-org poll → 404.
	if code, _ := f.req(t, "GET", "/api/v1/tenants/other/scaffold-runs/"+r.ID, "other", ""); code != http.StatusNotFound {
		t.Fatalf("want 404 for foreign run, got %d", code)
	}
	// Unknown run → 404.
	if code, _ := f.req(t, "GET", "/api/v1/tenants/acme/scaffold-runs/run:nope", "good", ""); code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown run, got %d", code)
	}

	// Cancel → 204; unknown → 404.
	if code, _ := f.req(t, "POST", "/api/v1/tenants/acme/scaffold-runs/"+r.ID+"/cancel", "good", ""); code != http.StatusNoContent {
		t.Fatalf("want 204 on cancel, got %d", code)
	}
	if code, _ := f.req(t, "POST", "/api/v1/tenants/acme/scaffold-runs/run:nope/cancel", "good", ""); code != http.StatusNotFound {
		t.Fatalf("want 404 cancelling unknown run, got %d", code)
	}
	// Terminal run → 409 (fresh run; the cancelled one above is a no-op).
	code, body = f.req(t, "POST", "/api/v1/tenants/acme/templates/go-service/runs", "good", `{"values":{"name":"orders-api"}}`)
	if code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", code, body)
	}
	var created2 struct {
		Run struct {
			ID string `json:"id"`
		} `json:"run"`
	}
	if err := json.Unmarshal([]byte(body), &created2); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.store.UpdateRunPhase(context.Background(), f.db.Pool, created2.Run.ID, types.ScaffoldPhaseCompleted, "", nil); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.req(t, "POST", "/api/v1/tenants/acme/scaffold-runs/"+created2.Run.ID+"/cancel", "good", ""); code != http.StatusConflict {
		t.Fatalf("want 409 cancelling terminal run, got %d", code)
	}
}
