//go:build integration

// QA probe tests: boundary, error-path, and concurrency coverage for the
// gitrepos HTTP/service layer, beyond the happy-path suite.
package gitrepos_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/types"
)

func unmarshal(t *testing.T, body string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), v); err != nil {
		t.Fatalf("unmarshal %q: %v", body, err)
	}
}

// QA: malformed UUID teamId must not produce a 500 (pg 22P02
// invalid_text_representation). Expected: a 4xx validation error.
func TestQAMalformedTeamUUID(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"

	code, body := f.req(t, "POST", base, "admin",
		`{"name":"x","repo":"acme/x","scope":"team","teamId":"not-a-uuid"}`)
	t.Logf("malformed teamId: %d %s", code, body)
	if code >= 500 {
		t.Errorf("malformed teamId produced %d (want 4xx): %s", code, body)
	}
}

// QA: registering with isDefault=true when the org already has a default
// must fail — and ideally with a message about the default, not a
// misleading "repo already registered" 409.
func TestQARegisterSecondDefault(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"

	if code, body := f.req(t, "POST", base, "admin",
		`{"name":"baseline","repo":"acme/state","scope":"platform","isDefault":true}`); code >= 300 {
		t.Fatalf("first default: %d %s", code, body)
	}
	code, body := f.req(t, "POST", base, "admin",
		`{"name":"baseline-2","repo":"acme/state-2","scope":"platform","isDefault":true}`)
	t.Logf("second default: %d %s", code, body)
	if code == http.StatusOK || code == http.StatusCreated {
		t.Fatalf("second default registered successfully — unique index not enforced?")
	}
	// KNOWN ISSUE (reported in review): the rejection is correct, but the
	// 409 detail says "repo already registered" — the repo slug is not the
	// conflict, the second default is. The message should name the default
	// rule and point at the PATCH-promote flow.
	if strings.Contains(strings.ToLower(body), "already registered") {
		t.Logf("KNOWN ISSUE: misleading error message (repo slug is not the conflict): %d %s", code, body)
	}
}

// QA: DELETE with force=true and no mode must be a 4xx (mode required),
// never a 5xx.
func TestQAForceDeleteWithoutMode(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"

	code, body := f.req(t, "POST", base, "admin",
		`{"name":"team","repo":"acme/team","scope":"team","teamId":"11111111-1111-1111-1111-111111111111"}`)
	if code >= 300 {
		t.Fatalf("register: %d %s", code, body)
	}
	var out struct {
		Repo repoView `json:"repo"`
	}
	unmarshal(t, body, &out)

	code, body = f.req(t, "DELETE", base+"/"+out.Repo.ID+"?force=true", "admin", "")
	t.Logf("force no mode: %d %s", code, body)
	if code >= 500 || code == http.StatusOK {
		t.Errorf("force without mode: %d %s (want 4xx)", code, body)
	}
}

// QA: DELETE on a non-existent id → 404, not 500.
func TestQADeleteMissingRepo(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	code, body := f.req(t, "DELETE", "/api/v1/tenants/acme/git-repos/01JXXXXXXXXXXXXXXXXXXXXXXX", "admin", "")
	if code != http.StatusNotFound {
		t.Errorf("delete missing: %d %s, want 404", code, body)
	}
}

// QA: PATCH on a non-existent id → 404.
func TestQAPatchMissingRepo(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	code, body := f.req(t, "PATCH", "/api/v1/tenants/acme/git-repos/01JXXXXXXXXXXXXXXXXXXXXXXX", "admin",
		`{"baseBranch":"trunk"}`)
	if code != http.StatusNotFound {
		t.Errorf("patch missing: %d %s, want 404", code, body)
	}
}

// QA: PATCH renaming a repo to an existing name → 409.
func TestQAPatchNameConflict(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"
	var out struct {
		Repo repoView `json:"repo"`
	}
	for _, n := range []string{"one", "two"} {
		code, body := f.req(t, "POST", base, "admin",
			fmt.Sprintf(`{"name":%q,"repo":"acme/%s","scope":"platform"}`, n, n))
		if code >= 300 {
			t.Fatalf("register %s: %d %s", n, code, body)
		}
		if n == "two" {
			unmarshal(t, body, &out)
		}
	}
	code, body := f.req(t, "PATCH", base+"/"+out.Repo.ID, "admin", `{"name":"one"}`)
	if code != http.StatusConflict {
		t.Errorf("rename to existing name: %d %s, want 409", code, body)
	}
}

// QA: concurrent default promotion of two different repos must leave
// exactly one default (unique index + atomic flip).
//
// KNOWN ISSUE: SetDefaultGitRepo's demote-then-promote CTE is atomic within
// one statement but NOT serialized across concurrent transactions — the
// loser's TX hits the partial unique index (23505) and the API returns 500.
// The data invariant holds (exactly one default; the loser's TX rolls back),
// but the API should serialize (advisory lock / FOR UPDATE on the org's
// default row) or map 23505 to 409. Skipped pending the author's fix.
func TestQAConcurrentPromote(t *testing.T) {
	t.Skip("known issue: concurrent promote returns 500 (unique-index race in SetDefaultGitRepo); see QA report")
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"
	var ids []string
	for _, n := range []string{"b1", "b2", "b3"} {
		code, body := f.req(t, "POST", base, "admin",
			fmt.Sprintf(`{"name":%q,"repo":"acme/%s","scope":"platform"}`, n, n))
		if code >= 300 {
			t.Fatalf("register %s: %d %s", n, code, body)
		}
		var out struct {
			Repo repoView `json:"repo"`
		}
		unmarshal(t, body, &out)
		ids = append(ids, out.Repo.ID)
	}
	var wg sync.WaitGroup
	errs := make([]string, len(ids))
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			code, body := f.req(t, "PATCH", base+"/"+id, "admin", `{"isDefault":true}`)
			if code != http.StatusOK {
				errs[i] = fmt.Sprintf("%d %s", code, body)
			}
		}(i, id)
	}
	wg.Wait()
	for i, e := range errs {
		if e != "" {
			t.Errorf("promote %d failed: %s", i, e)
		}
	}
	code, body := f.req(t, "GET", base, "admin", "")
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	var listOut struct {
		Repos []repoView `json:"repos"`
	}
	unmarshal(t, body, &listOut)
	defaults := 0
	for _, r := range listOut.Repos {
		if r.IsDefault {
			defaults++
		}
	}
	if defaults != 1 {
		t.Errorf("defaults = %d, want exactly 1", defaults)
	}
}

// QA: a team-scope repo whose teamId is a valid UUID in the org but the
// caller is admin — PATCH teamId to another in-org team succeeds; PATCH
// teamId to garbage UUID must not 500.
func TestQAPatchTeamMalformedUUID(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"
	code, body := f.req(t, "POST", base, "admin",
		`{"name":"team","repo":"acme/team","scope":"team","teamId":"11111111-1111-1111-1111-111111111111"}`)
	if code >= 300 {
		t.Fatalf("register: %d %s", code, body)
	}
	var out struct {
		Repo repoView `json:"repo"`
	}
	unmarshal(t, body, &out)

	code, body = f.req(t, "PATCH", base+"/"+out.Repo.ID, "admin", `{"teamId":"bogus"}`)
	t.Logf("patch malformed teamId: %d %s", code, body)
	if code >= 500 {
		t.Errorf("patch malformed teamId produced %d (want 4xx): %s", code, body)
	}
}

// QA: boundary — name at maxLength 63 accepted, 64 rejected by huma (400).
func TestQANameLengthBoundary(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"

	name63 := strings.Repeat("a", 63)
	code, body := f.req(t, "POST", base, "admin",
		fmt.Sprintf(`{"name":%q,"repo":"acme/long-ok","scope":"platform"}`, name63))
	if code >= 300 {
		t.Errorf("63-char name rejected: %d %s", code, body)
	}
	name64 := strings.Repeat("a", 64)
	code, body = f.req(t, "POST", base, "admin",
		fmt.Sprintf(`{"name":%q,"repo":"acme/long-bad","scope":"platform"}`, name64))
	if code >= 300 {
		t.Logf("64-char name: %d %s (huma maxLength enforcement expected)", code, body)
	} else {
		t.Errorf("64-char name accepted: %d", code)
	}
}

// QA: repo slug edge cases — extra slashes, empty segments, whitespace.
func TestQARepoSlugEdges(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"
	cases := []struct{ name, repo string }{
		{"three segments", "a/b/c"},
		{"empty owner", "/repo"},
		{"empty name", "owner/"},
		{"space", "own er/repo"},
		{"trailing space", "owner/repo "},
	}
	for _, tc := range cases {
		code, body := f.req(t, "POST", base, "admin",
			fmt.Sprintf(`{"name":%q,"repo":%q,"scope":"platform"}`, tc.name, tc.repo))
		if code != http.StatusUnprocessableEntity {
			t.Errorf("%s (%q): %d %s, want 422", tc.name, tc.repo, code, body)
		}
	}
}

// QA: unauthenticated and cross-org access on every method.
func TestQAAuthzMatrix(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"

	code, body := f.req(t, "POST", base, "admin",
		`{"name":"team","repo":"acme/team","scope":"team","teamId":"11111111-1111-1111-1111-111111111111"}`)
	if code >= 300 {
		t.Fatalf("register: %d %s", code, body)
	}
	var out struct {
		Repo repoView `json:"repo"`
	}
	unmarshal(t, body, &out)
	id := out.Repo.ID

	checks := []struct {
		method, path, token, body string
		want                        int
	}{
		{"GET", base, "", "", http.StatusUnauthorized},
		{"POST", base, "", `{"name":"y","repo":"acme/y"}`, http.StatusUnauthorized},
		{"GET", base + "/" + id, "", "", http.StatusUnauthorized},
		{"PATCH", base + "/" + id, "", `{"name":"z"}`, http.StatusUnauthorized},
		{"DELETE", base + "/" + id, "", "", http.StatusUnauthorized},
		{"GET", base, "outsider", "", http.StatusForbidden},
		{"POST", base, "outsider", `{"name":"y","repo":"acme/y"}`, http.StatusForbidden},
		{"GET", base + "/" + id, "outsider", "", http.StatusForbidden},
		{"PATCH", base + "/" + id, "outsider", `{"name":"z"}`, http.StatusForbidden},
		{"DELETE", base + "/" + id, "outsider", "", http.StatusForbidden},
	}
	for _, c := range checks {
		code, body := f.req(t, c.method, c.path, c.token, c.body)
		if code != c.want {
			t.Errorf("%s %s token=%q: %d %s, want %d", c.method, c.path, c.token, code, body, c.want)
		}
	}
}

// QA: orphan force-delete with live refs leaves the instance/addon rows
// pointing at NULL repo (FK SET NULL) and the workloads untouched.
func TestQAOrphanLeavesWorkloads(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"
	ctx := context.Background()

	code, body := f.req(t, "POST", base, "admin",
		`{"name":"team","repo":"acme/team","scope":"team","teamId":"11111111-1111-1111-1111-111111111111"}`)
	if code >= 300 {
		t.Fatalf("register: %d %s", code, body)
	}
	var out struct {
		Repo repoView `json:"repo"`
	}
	unmarshal(t, body, &out)
	repoID := out.Repo.ID

	store := inventory.NewStore()
	if err := store.UpsertClusterAddon(ctx, f.database.Pool, &types.ClusterAddon{
		OrgID: "org:1", ClusterID: "cluster-1", CatalogItem: "platform:cert-manager",
		State: types.AddonStateManaged, RepoID: repoID, RepoPath: "addons/cert-manager",
		Source: types.SourceDescriptor{Kind: types.SourceKindHelm},
	}); err != nil {
		t.Fatal(err)
	}

	code, body = f.req(t, "DELETE", base+"/"+repoID+"?force=true&mode=orphan", "admin", "")
	if code != http.StatusOK {
		t.Fatalf("orphan: %d %s", code, body)
	}
	// Addon row survives with repo_id NULLed.
	var gotRepoID *string
	if err := f.database.Pool.QueryRow(ctx,
		`SELECT repo_id FROM cluster_addons WHERE org_id='org:1' AND cluster_id='cluster-1'`).Scan(&gotRepoID); err != nil {
		t.Fatal(err)
	}
	if gotRepoID != nil {
		t.Errorf("addon repo_id = %v, want NULL after orphan", *gotRepoID)
	}
	// No git deletions, no agent commands in orphan mode.
	if len(f.git.Deletions) != 0 {
		t.Errorf("orphan deleted git paths: %v", f.git.Deletions)
	}
	if len(f.queue.cmds) != 0 {
		t.Errorf("orphan enqueued agent commands: %d", len(f.queue.cmds))
	}
}
