//go:build integration

// QA probes (M8.W5 QA phase): adversarial requests against the full HTTP
// stack — malformed bodies, boundary inputs, idempotency edge cases.
package scaffold

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Malformed / boundary request bodies on the UI adapter route.
func TestQAMalformedBodies(t *testing.T) {
	f := newITFixture(t)

	cases := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"empty object", `{}`},
		{"null fields", `{"templateId":null,"name":null,"parameters":null}`},
		{"parameters as string", `{"templateId":"template:go-service","name":"x","parameters":"nope"}`},
		{"parameters as array", `{"templateId":"template:go-service","name":"x","parameters":[1,2]}`},
		{"empty templateId", `{"templateId":"","name":"x","parameters":{"name":"payments-api"}}`},
	}
	for _, tc := range cases {
		code, body := f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "good", tc.body)
		if code >= 500 {
			t.Errorf("%s: got %d (server error): %s", tc.name, code, body)
		} else {
			t.Logf("%s: %d %s", tc.name, code, body)
		}
	}
	var n int
	if err := f.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM scaffold_runs`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("no probe may create a run row, got %d (%v)", n, err)
	}
}

// Unauthenticated requests on the UI adapter routes.
func TestQAUnauthenticated(t *testing.T) {
	f := newITFixture(t)
	if code, _ := f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "",
		`{"templateId":"template:go-service","name":"x","parameters":{"name":"payments-api"}}`); code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", code)
	}
	if code, _ := f.req(t, "GET", "/api/v1/tenants/acme/scaffolds/run:x", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", code)
	}
}

// Semantically equal values with different numeric literals (2 vs 2.0)
// must not fork two runs — the idempotency key should canonicalize numbers.
func TestQANumericLiteralIdempotency(t *testing.T) {
	f := newITFixture(t)
	body1 := `{"templateId":"template:go-service","name":"a","parameters":{"name":"payments-api","replicas":2}}`
	body2 := `{"templateId":"template:go-service","name":"a","parameters":{"name":"payments-api","replicas":2.0}}`
	code1, resp1 := f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "good", body1)
	code2, resp2 := f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "good", body2)
	t.Logf("first: %d, second: %d", code1, code2)
	var n int
	if err := f.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM scaffold_runs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("replicas 2 vs 2.0 forked %d runs (idempotency leak)\n%s\n%s", n, resp1, resp2)
	}
}

// A wizard value that passes schema validation but cannot slugify into a
// component name must fail the run with an actionable error, not wedge it.
func TestQAUnslugifiableComponentName(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{"a.txt.tmpl": "x"})
	f.svc.WithExecEnv(&ExecEnv{
		Git: gitprovider.NewFake(), GitOrg: "acme-platform", Registrar: &fakeRegistrar{},
		Upsert: &fakeUpserter{}, RBAC: &fakeRBACBinder{},
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(),
	})

	// "!!!" is 3 chars so it passes minLength:3 and additionalProperties:false.
	code, body := f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "good",
		`{"templateId":"template:go-service","name":"!!!","parameters":{"name":"!!!"}}`)
	if code != http.StatusCreated {
		t.Fatalf("want 201 (schema-valid), got %d: %s", code, body)
	}

	// Drive to terminal: each failure re-enters after backoff, so rewind the
	// step clock between ticks until the attempt budget is exhausted.
	var got *types.ScaffoldRun
	for range 10 {
		f.svc.reconcileOnce(ctx, time.Minute)
		got, _, _ = f.svc.GetRun(ctx, "org:acme", decodeScaffold(t, body).ID)
		if got.Phase == types.ScaffoldPhaseFailed {
			break
		}
		if _, err := f.db.Pool.Exec(ctx,
			`UPDATE scaffold_run_steps SET updated_at = now() - interval '1 day' WHERE run_id = $1`, got.ID); err != nil {
			t.Fatal(err)
		}
	}
	if got.Phase != types.ScaffoldPhaseFailed {
		t.Fatalf("unslugifiable name must settle failed, got %q", got.Phase)
	}
	t.Logf("settled error: %s", got.Error)
	if !strings.Contains(got.Error, "component name") {
		t.Fatalf("error must name the cause, got %q", got.Error)
	}
}

// Cancel via the canonical route a run created through the UI adapter;
// the UI poll surface must then reflect the settled failure.
func TestQACancelCrossSurface(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{"a.txt.tmpl": "x"})
	f.svc.WithExecEnv(&ExecEnv{
		Git: gitprovider.NewFake(), GitOrg: "acme-platform", Registrar: &fakeRegistrar{},
		Upsert: &fakeUpserter{}, RBAC: &fakeRBACBinder{},
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(),
	})

	code, body := f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "good",
		`{"templateId":"template:go-service","name":"payments-api","parameters":{"name":"payments-api"}}`)
	if code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", code, body)
	}
	id := decodeScaffold(t, body).ID

	// Cancel while idle (before any reconcile) via the canonical route.
	if code, _ := f.req(t, "POST", "/api/v1/tenants/acme/scaffold-runs/"+id+"/cancel", "good", ""); code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", code)
	}
	f.svc.reconcileOnce(ctx, time.Minute)

	code, body = f.req(t, "GET", "/api/v1/tenants/acme/scaffolds/"+id, "good", "")
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	sc := decodeScaffold(t, body)
	if sc.Phase != "failed" || sc.Message == nil || *sc.Message != "cancelled" {
		t.Fatalf("UI poll after cancel = %+v", sc)
	}
}

// Replay through the adapter with a *different* top-level name but
// identical parameters: idempotency keys on parameters, so the UI gets the
// original run back — verify the response reflects the stored display name.
func TestQAReplayDifferentDisplayName(t *testing.T) {
	f := newITFixture(t)
	mk := func(name string) (int, string) {
		return f.req(t, "POST", "/api/v1/tenants/acme/scaffolds", "good",
			`{"templateId":"template:go-service","name":"`+name+`","parameters":{"name":"payments-api"}}`)
	}
	code, body := mk("first-name")
	if code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", code, body)
	}
	code, body2 := mk("second-name")
	if code != http.StatusOK {
		t.Fatalf("want 200 replay, got %d", code)
	}
	if decodeScaffold(t, body).ID != decodeScaffold(t, body2).ID {
		t.Fatalf("same parameters must replay the same run")
	}
	t.Logf("replay name: %q (created as %q)", decodeScaffold(t, body2).Name, decodeScaffold(t, body).Name)
}

// Canonical create with the template addressed by catalog item ID
// (the UI routes by id) and no explicit version.
func TestQACanonicalCreateByItemID(t *testing.T) {
	f := newITFixture(t)
	code, body := f.req(t, "POST", "/api/v1/tenants/acme/templates/template:go-service/runs", "good",
		`{"values":{"name":"payments-api"}}`)
	if code != http.StatusCreated {
		t.Fatalf("want 201 addressing by item ID, got %d: %s", code, body)
	}
	if !strings.Contains(body, `"templateName":"go-service"`) {
		t.Fatalf("templateName must resolve from item ID: %s", body)
	}
}
