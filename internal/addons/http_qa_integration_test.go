//go:build integration

// QA probes for the addons REST surface: boundary values, error paths, and
// authn/authz negatives beyond the happy-path suite.
package addons_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

// Values that are valid JSON but not an object must be a 422 (client
// error), never a 500 — including for catalog items with no values schema
// (decision 4's lenient fallback must not skip shape validation).
func TestQAAdoptNonObjectValues(t *testing.T) {
	f := newITServer(t, types.CommitPolicyDirect)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/clusters/cluster-1/addons"

	for _, values := range []string{`"just-a-string"`, `[1,2,3]`, `42`, `true`} {
		// external-secrets has NO schema: the lenient fallback path.
		code, body := f.req(t, http.MethodPost, base+"/platform:external-secrets/adopt", "admin",
			`{"version":"v0.12.1","values":`+values+`}`)
		if code != http.StatusUnprocessableEntity {
			t.Errorf("no-schema item, values=%s: got %d (%s), want 422", values, code, body)
		}
		// cert-manager HAS a schema: same expectation.
		code, body = f.req(t, http.MethodPost, base+"/platform:cert-manager/adopt", "admin",
			`{"version":"v1.16.1","values":`+values+`}`)
		if code != http.StatusUnprocessableEntity {
			t.Errorf("schema item, values=%s: got %d (%s), want 422", values, code, body)
		}
	}
	// Nothing must have been committed or registered by the rejected calls.
	if files := f.git.Files("acme/acme-inari-state", "main"); len(files) != 0 {
		t.Errorf("rejected adopts committed files: %v", files)
	}
	if len(f.queue.cmds) != 0 {
		t.Errorf("rejected adopts enqueued commands: %+v", f.queue.cmds)
	}
}

// Authn/authz negatives: no token → 401, non-member → 403, member without
// the relation → 403, and cross-org cluster references → 404.
func TestQAAuthzBoundaries(t *testing.T) {
	f := newITServer(t, types.CommitPolicyDirect)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/clusters/cluster-1/addons"

	if code, _ := f.req(t, http.MethodGet, base, "", ""); code != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", code)
	}
	if code, _ := f.req(t, http.MethodGet, base, "garbage", ""); code != http.StatusUnauthorized {
		t.Errorf("bad token: got %d, want 401", code)
	}
	if code, _ := f.req(t, http.MethodGet, base, "outsider", ""); code != http.StatusForbidden {
		t.Errorf("non-member: got %d, want 403", code)
	}
	// A cluster that does not exist in this org must 404 on adopt, not
	// silently resolve.
	code, _ := f.req(t, http.MethodPost, "/api/v1/tenants/acme/clusters/cluster-999/addons/platform:cert-manager/adopt", "admin",
		`{"version":"v1.16.1"}`)
	if code != http.StatusNotFound {
		t.Errorf("unknown cluster adopt: got %d, want 404", code)
	}
	// Listing a foreign/unknown cluster's addons yields an empty page (no
	// cross-tenant leak), not an error.
	code, body := f.req(t, http.MethodGet, "/api/v1/tenants/acme/clusters/cluster-999/addons", "admin", "")
	if code != http.StatusOK || !strings.Contains(body, `"addons":[]`) {
		t.Errorf("unknown cluster list: got %d %s, want 200 empty", code, body)
	}
}

// Lifecycle state-machine negatives: adopt twice → 409; update/enable-prune
// on a discovered (unmanaged) addon → 409; enable-prune twice → 409;
// unknown addon → 404.
func TestQAStateMachineNegatives(t *testing.T) {
	f := newITServer(t, types.CommitPolicyDirect)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/clusters/cluster-1/addons"

	// Discover, then try to update/enable-prune before adopting.
	_, err := f.database.Pool.Exec(t.Context(), `
		INSERT INTO cluster_addons (id, org_id, cluster_id, catalog_item, state, source)
		VALUES ('addon-disc', 'org:1', 'cluster-1', 'platform:external-secrets', 'discovered', '{"kind":"helm","helm":{"repoURL":"r","chart":"c","version":"v0"}}')`)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := f.req(t, http.MethodPatch, "/api/v1/tenants/acme/addons/addon-disc", "admin",
		`{"chartVersion":"v0.12.1"}`); code != http.StatusConflict {
		t.Errorf("update discovered: got %d (%s), want 409", code, body)
	}
	if code, body := f.req(t, http.MethodPost, "/api/v1/tenants/acme/addons/addon-disc/enable-prune", "admin",
		""); code != http.StatusConflict {
		t.Errorf("enable-prune discovered: got %d (%s), want 409", code, body)
	}

	// Adopt it, then adopt again → 409.
	code, body := f.req(t, http.MethodPost, base+"/platform:external-secrets/adopt", "admin",
		`{"version":"v0.12.1"}`)
	if code != http.StatusOK {
		t.Fatalf("adopt: %d %s", code, body)
	}
	var out struct {
		Addon struct {
			ID string `json:"id"`
		} `json:"addon"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if code, body := f.req(t, http.MethodPost, base+"/platform:external-secrets/adopt", "admin",
		`{"version":"v0.12.1"}`); code != http.StatusConflict {
		t.Errorf("re-adopt: got %d (%s), want 409", code, body)
	}

	// enable-prune twice: first 200, second 409.
	if code, body := f.req(t, http.MethodPost, "/api/v1/tenants/acme/addons/"+out.Addon.ID+"/enable-prune", "admin", ""); code != http.StatusOK {
		t.Fatalf("enable-prune: %d %s", code, body)
	}
	if code, body := f.req(t, http.MethodPost, "/api/v1/tenants/acme/addons/"+out.Addon.ID+"/enable-prune", "admin", ""); code != http.StatusConflict {
		t.Errorf("enable-prune twice: got %d (%s), want 409", code, body)
	}

	// Unknown addon ID → 404 on both mutations.
	if code, _ := f.req(t, http.MethodPatch, "/api/v1/tenants/acme/addons/addon-nope", "admin", `{"chartVersion":"v1"}`); code != http.StatusNotFound {
		t.Errorf("update unknown: got %d, want 404", code)
	}
	if code, _ := f.req(t, http.MethodPost, "/api/v1/tenants/acme/addons/addon-nope/enable-prune", "admin", ""); code != http.StatusNotFound {
		t.Errorf("enable-prune unknown: got %d, want 404", code)
	}
}

// Input-validation boundaries: enum violations, namespace pattern, unknown
// catalog item/version, empty PATCH body, and malformed JSON.
func TestQAInputValidation(t *testing.T) {
	f := newITServer(t, types.CommitPolicyDirect)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/clusters/cluster-1/addons"

	cases := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{"bad deployMode", http.MethodPost, base + "/platform:cert-manager/adopt", `{"deployMode":"fleet"}`, http.StatusUnprocessableEntity},
		{"bad namespace", http.MethodPost, base + "/platform:cert-manager/adopt", `{"namespace":"Bad_NS"}`, http.StatusUnprocessableEntity},
		{"namespace too long", http.MethodPost, base + "/platform:cert-manager/adopt", `{"namespace":"` + strings.Repeat("a", 64) + `"}`, http.StatusUnprocessableEntity},
		{"unknown catalog item", http.MethodPost, base + "/platform:does-not-exist/adopt", `{}`, http.StatusNotFound},
		{"unknown version", http.MethodPost, base + "/platform:cert-manager/adopt", `{"version":"v9.9.9"}`, http.StatusNotFound},
		{"malformed json", http.MethodPost, base + "/platform:cert-manager/adopt", `{"values":`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		code, body := f.req(t, tc.method, tc.path, "admin", tc.body)
		if code != tc.wantStatus {
			t.Errorf("%s: got %d (%s), want %d", tc.name, code, body, tc.wantStatus)
		}
	}

	// Empty PATCH body → 422 (nothing to update).
	if code, body := f.req(t, http.MethodPatch, "/api/v1/tenants/acme/addons/whatever", "admin", `{}`); code != http.StatusUnprocessableEntity {
		t.Errorf("empty patch: got %d (%s), want 422", code, body)
	}
}
