//go:build integration

package approvals

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
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// itValidator maps test tokens to identities: "good" belongs to acme+acme2,
// "acme-only" to acme alone, "outsider" to an unrelated org; anything else is
// rejected.
type itValidator struct{}

func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "good":
		return &authn.Identity{Subject: "user-1", Organizations: []string{"acme", "acme2"}}, nil
	case "acme-only":
		return &authn.Identity{Subject: "user-3", Organizations: []string{"acme"}}, nil
	case "outsider":
		return &authn.Identity{Subject: "user-2", Organizations: []string{"other"}}, nil
	case "drifter":
		return &authn.Identity{Subject: "user-4", Organizations: []string{"ghost", "acme"}}, nil
	}
	return nil, errInvalidTestToken
}

var errInvalidTestToken = errors.New("invalid token")

// itAuthorizer allows viewer checks per org ID listed in allow; an empty map
// denies everything. errOn, when set, makes Check fail for that org object
// (inbox must omit the org silently).
type itAuthorizer struct {
	allow map[string]bool
	errOn string
}

func (a itAuthorizer) Check(_ context.Context, _, _, object string) (bool, error) {
	if a.errOn != "" && object == a.errOn {
		return false, errors.New("fga unavailable")
	}
	return a.allow[object], nil
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

func allowAll() itAuthorizer {
	return itAuthorizer{allow: map[string]bool{"organization:org:1": true, "organization:org:2": true, "organization:org:3": true}}
}

func itServer(t *testing.T, az itAuthorizer) (*httptest.Server, *db.DB) {
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
		 ('org:1','acme','Acme','kc-1'), ('org:2','acme2','Acme2','kc-2'), ('org:3','other','Other','kc-3')`); err != nil {
		t.Fatal(err)
	}
	svc := NewService(database, NewStore(database), audit.NewStore(), nil, nil)
	h := NewHandler(svc, itTenants{
		"acme":  {ID: "org:1", Slug: "acme"},
		"acme2": {ID: "org:2", Slug: "acme2"},
		"other": {ID: "org:3", Slug: "other"},
	}, az)
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	h.RegisterRoutes(api)
	return httptest.NewServer(router), database
}

func itReq(t *testing.T, srv *httptest.Server, path, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// itSeed inserts a lifecycle approval request with an explicit created_at so
// cross-org ordering is deterministic. Returns the generated id.
func itSeed(t *testing.T, database *db.DB, orgID, state, name string, createdAt time.Time) string {
	t.Helper()
	var id string
	err := database.Pool.QueryRow(context.Background(),
		`INSERT INTO approval_requests (org_id, item_id, version, cluster_id, spec, requester, action, name, state, created_at)
		 VALUES ($1, NULL, '', '', '{}', 'user:req-1', 'cluster.decommission', $2, $3, $4) RETURNING id`,
		orgID, name, state, createdAt).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func inboxItems(t *testing.T, body string) []types.ApprovalRequest {
	t.Helper()
	var out struct {
		Items []types.ApprovalRequest `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out.Items
}

func itemIDs(items []types.ApprovalRequest) []string {
	ids := make([]string, len(items))
	for i, r := range items {
		ids[i] = r.ID
	}
	return ids
}

// TestInboxAggregatesAcrossOrgs verifies the caller-scoped aggregate: pending
// approvals from all of the caller's orgs, createdAt desc with id tie-break,
// non-pending rows excluded, authz parity with the per-org route.
func TestInboxAggregatesAcrossOrgs(t *testing.T) {
	srv, database := itServer(t, allowAll())
	defer srv.Close()
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	old1 := itSeed(t, database, "org:1", "pending", "acme-old", base)
	itSeed(t, database, "org:1", "approved", "acme-decided", base.Add(4*time.Hour))
	new2 := itSeed(t, database, "org:2", "pending", "acme2-new", base.Add(2*time.Hour))
	tieA := itSeed(t, database, "org:1", "pending", "acme-tie", base.Add(time.Hour))
	tieB := itSeed(t, database, "org:2", "pending", "acme2-tie", base.Add(time.Hour))
	other := itSeed(t, database, "org:3", "pending", "other-pending", base.Add(3*time.Hour))

	// Authz parity, direction 1: visible per org route -> visible in inbox.
	code, body := itReq(t, srv, "/api/v1/tenants/acme/approvals", "good")
	if code != http.StatusOK {
		t.Fatalf("per-org list: %d %s", code, body)
	}
	var perOrg struct {
		Approvals []types.ApprovalRequest `json:"approvals"`
	}
	if err := json.Unmarshal([]byte(body), &perOrg); err != nil {
		t.Fatal(err)
	}
	perOrgIDs := map[string]bool{}
	for _, r := range perOrg.Approvals {
		perOrgIDs[r.ID] = true
	}

	code, body = itReq(t, srv, "/api/v1/approvals/inbox", "good")
	if code != http.StatusOK {
		t.Fatalf("inbox: %d %s", code, body)
	}
	items := inboxItems(t, body)
	inboxIDs := map[string]bool{}
	for _, r := range items {
		inboxIDs[r.ID] = true
		if r.State != string(types.ApprovalStatePending) {
			t.Errorf("non-pending item in inbox: %s state=%s", r.ID, r.State)
		}
	}
	for id := range perOrgIDs {
		if !inboxIDs[id] {
			t.Errorf("per-org visible approval %s missing from inbox", id)
		}
	}
	// Direction 2: every inbox item is visible via its own per-org route.
	for _, r := range items {
		slug := "acme"
		if r.OrgID == "org:2" {
			slug = "acme2"
		}
		code, b := itReq(t, srv, "/api/v1/tenants/"+slug+"/approvals/"+r.ID, "good")
		if code != http.StatusOK {
			t.Errorf("inbox item %s not visible via per-org route: %d %s", r.ID, code, b)
		}
	}

	// Cross-org ordering: createdAt desc, id asc on ties.
	wantOrder := []string{new2}
	if tieA < tieB {
		wantOrder = append(wantOrder, tieA, tieB)
	} else {
		wantOrder = append(wantOrder, tieB, tieA)
	}
	wantOrder = append(wantOrder, old1)
	got := itemIDs(items)
	if len(got) != len(wantOrder) {
		t.Fatalf("inbox ids = %v, want %v", got, wantOrder)
	}
	for i := range wantOrder {
		if got[i] != wantOrder[i] {
			t.Fatalf("inbox order = %v, want %v", got, wantOrder)
		}
	}
	// Non-member org never leaks, even though "good" passes the org:3 check.
	for _, id := range got {
		if id == other {
			t.Error("inbox leaked an approval from an org the caller does not belong to")
		}
	}
}

// TestInboxOmitsForbiddenOrgs verifies partial access never 403s: orgs denied
// by OpenFGA (or erroring) are silently omitted while allowed orgs still list.
func TestInboxOmitsForbiddenOrgs(t *testing.T) {
	srv, database := itServer(t, itAuthorizer{allow: map[string]bool{"organization:org:1": true}})
	defer srv.Close()
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	allowed := itSeed(t, database, "org:1", "pending", "acme", base)
	forbidden := itSeed(t, database, "org:2", "pending", "acme2", base.Add(time.Hour))

	code, body := itReq(t, srv, "/api/v1/approvals/inbox", "good")
	if code != http.StatusOK {
		t.Fatalf("inbox with partial access: %d %s", code, body)
	}
	got := itemIDs(inboxItems(t, body))
	if len(got) != 1 || got[0] != allowed {
		t.Errorf("inbox = %v, want only [%s]", got, allowed)
	}
	for _, id := range got {
		if id == forbidden {
			t.Error("inbox leaked an approval from a forbidden org")
		}
	}

	// FGA errors are treated the same as denials.
	srv2, database2 := itServer(t, itAuthorizer{
		allow: map[string]bool{"organization:org:1": true},
		errOn: "organization:org:2",
	})
	defer srv2.Close()
	itSeed(t, database2, "org:1", "pending", "acme", base)
	itSeed(t, database2, "org:2", "pending", "acme2", base)
	code, body = itReq(t, srv2, "/api/v1/approvals/inbox", "good")
	if code != http.StatusOK {
		t.Fatalf("inbox with fga error: %d %s", code, body)
	}
	if got := inboxItems(t, body); len(got) != 1 {
		t.Errorf("inbox = %d items, want 1 (erroring org omitted)", len(got))
	}
}

// TestInboxEmptyAndLimit covers the empty envelope and limit clamping.
func TestInboxEmptyAndLimit(t *testing.T) {
	srv, database := itServer(t, allowAll())
	defer srv.Close()
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	// Empty result is {"items":[]}, not null and not an error.
	code, body := itReq(t, srv, "/api/v1/approvals/inbox", "good")
	if code != http.StatusOK {
		t.Fatalf("empty inbox: %d %s", code, body)
	}
	if !strings.Contains(body, `"items":[]`) {
		t.Errorf("empty inbox body = %s, want items:[]", body)
	}
	// Caller with no resolvable orgs also gets an empty inbox.
	code, body = itReq(t, srv, "/api/v1/approvals/inbox", "outsider")
	if code != http.StatusOK {
		t.Fatalf("outsider inbox: %d %s", code, body)
	}
	if !strings.Contains(body, `"items":[]`) {
		t.Errorf("outsider inbox body = %s, want items:[]", body)
	}
	// Unauthenticated is still rejected by middleware.
	if code, _ := itReq(t, srv, "/api/v1/approvals/inbox", ""); code != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", code)
	}

	var ids []string
	for i := 0; i < 3; i++ {
		ids = append(ids, itSeed(t, database, "org:1", "pending", fmt.Sprintf("a%d", i), base.Add(time.Duration(i)*time.Hour)))
	}
	code, body = itReq(t, srv, "/api/v1/approvals/inbox?limit=1", "acme-only")
	if code != http.StatusOK {
		t.Fatalf("limit=1: %d %s", code, body)
	}
	if got := itemIDs(inboxItems(t, body)); len(got) != 1 || got[0] != ids[2] {
		t.Errorf("limit=1 inbox = %v, want [%s] (newest)", got, ids[2])
	}
	// Over-max limit is clamped, not an error.
	code, body = itReq(t, srv, "/api/v1/approvals/inbox?limit=999", "acme-only")
	if code != http.StatusOK {
		t.Fatalf("limit=999: %d %s", code, body)
	}
	if got := inboxItems(t, body); len(got) != 3 {
		t.Errorf("limit=999 inbox = %d items, want 3", len(got))
	}
}

// TestInboxSkipsUnresolvableOrgs verifies claim/org drift: an org slug in the
// JWT that no longer resolves in tenancy is omitted silently, while the
// caller's remaining orgs still list.
func TestInboxSkipsUnresolvableOrgs(t *testing.T) {
	srv, database := itServer(t, allowAll())
	defer srv.Close()
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	seeded := itSeed(t, database, "org:1", "pending", "acme", base)

	code, body := itReq(t, srv, "/api/v1/approvals/inbox", "drifter")
	if code != http.StatusOK {
		t.Fatalf("drifter inbox: %d %s", code, body)
	}
	got := itemIDs(inboxItems(t, body))
	if len(got) != 1 || got[0] != seeded {
		t.Errorf("drifter inbox = %v, want [%s] (ghost org skipped)", got, seeded)
	}
}
