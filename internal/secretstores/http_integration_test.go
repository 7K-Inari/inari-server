//go:build integration

package secretstores_test

import (
	"bytes"
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

	"github.com/7K-Inari/inari-server/internal/agentgateway"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/secretstores"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Tokens: "admin" (org admin + platform superuser), "viewer" (viewer only),
// "outsider" (member of an unrelated org). Anything else is rejected.
type itValidator struct{}

func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "admin":
		return &authn.Identity{Subject: "user-admin", Organizations: []string{"acme"}}, nil
	case "orgadmin":
		return &authn.Identity{Subject: "user-orgadmin", Organizations: []string{"acme"}}, nil
	case "viewer":
		return &authn.Identity{Subject: "user-viewer", Organizations: []string{"acme"}}, nil
	case "outsider":
		return &authn.Identity{Subject: "user-out", Organizations: []string{"other"}}, nil
	}
	return nil, errors.New("invalid token")
}

// itAuthorizer: viewer gets viewer on org:1, admin gets admin on org:1 plus
// superuser on platform:inari.
type itAuthorizer struct{}

func (itAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	switch {
	case object == authz.ObjectPlatform && relation == authz.RelationSuperuser:
		return user == authz.UserObject("user-admin"), nil
	case object == authz.OrgObject("org:1") && relation == authz.RelationAdmin:
		return user == authz.UserObject("user-admin") || user == authz.UserObject("user-orgadmin"), nil
	case object == authz.OrgObject("org:1") && relation == authz.RelationViewer:
		return true, nil
	}
	return false, nil
}

func (itAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type itTenants map[string]*types.Organization

func (t itTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if o, ok := t[slug]; ok {
		return o, nil
	}
	return nil, tenancy.ErrOrgNotFound
}

type itClusters struct{ clusters []types.Cluster }

func (c *itClusters) ListClusters(_ context.Context, orgID string) ([]types.Cluster, error) {
	var out []types.Cluster
	for _, cl := range c.clusters {
		if cl.OrgID == orgID {
			out = append(out, cl)
		}
	}
	return out, nil
}

// itSets only supports the pre-seeded "prod" set; tests otherwise target
// explicit clusterIds.
type itSets struct{ clusters *itClusters }

func (s *itSets) GetClusterSet(_ context.Context, orgID, id string) (*types.ClusterSet, error) {
	if id == "prod" {
		return &types.ClusterSet{ID: "prod", OrgID: orgID, LabelSelector: map[string]string{"env": "prod"}}, nil
	}
	return nil, errors.New("unknown set")
}

func (s *itSets) ResolveClusters(_ context.Context, orgID string, selector map[string]string) ([]types.Cluster, error) {
	var out []types.Cluster
	for _, cl := range s.clusters.clusters {
		if cl.OrgID != orgID {
			continue
		}
		match := true
		for k, v := range selector {
			if cl.Labels[k] != v {
				match = false
				break
			}
		}
		if match {
			out = append(out, cl)
		}
	}
	return out, nil
}

func itServer(t *testing.T) (*httptest.Server, *db.DB) {
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
		 ('org:1','acme','Acme','kc-1'), ('org:2','other','Other','kc-2');
		 INSERT INTO clusters (id, org_id, name, state, labels) VALUES
		 ('cluster:1','org:1','prod-eu','active','{"env":"prod"}'),
		 ('cluster:2','org:1','dev','active','{"env":"dev"}')`); err != nil {
		t.Fatal(err)
	}
	clusters := &itClusters{clusters: []types.Cluster{
		{ID: "cluster:1", OrgID: "org:1", Name: "prod-eu", Labels: map[string]string{"env": "prod"}},
		{ID: "cluster:2", OrgID: "org:1", Name: "dev", Labels: map[string]string{"env": "dev"}},
	}}
	// Real queue: fan-out commands must land in agent_commands so the status
	// projection reads the same rows agents ack against.
	queue := agentgateway.NewQueue(database, time.Minute)
	svc := secretstores.NewService(database, secretstores.NewStore(), audit.NewStore(),
		queue, clusters, &itSets{clusters: clusters})
	h := secretstores.NewHandler(svc, itTenants{
		"acme":  {ID: "org:1", Slug: "acme"},
		"other": {ID: "org:2", Slug: "other"},
	}, itAuthorizer{})
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	h.RegisterRoutes(api)
	return httptest.NewServer(router), database
}

func itDo(t *testing.T, srv *httptest.Server, method, path, token string, body any) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, rdr)
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

func vaultProvider() map[string]any {
	return map[string]any{
		"vault": map[string]any{
			"server":        "https://vault.example.com",
			"authSecretRef": map[string]any{"name": "vault-token", "namespace": "inari-system"},
		},
	}
}

func commandIDs(t *testing.T, database *db.DB) []string {
	t.Helper()
	rows, err := database.Pool.Query(context.Background(),
		`SELECT id FROM agent_commands ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

// TestSecretStoreCRUD covers the happy path: create fans out apply commands,
// list/get/status reflect the store, patch updates it, delete fans out delete
// commands, and every mutation leaves an audit row.
func TestSecretStoreCRUD(t *testing.T) {
	srv, database := itServer(t)
	defer srv.Close()
	ctx := context.Background()

	// Create: admin only, fans out one apply command per target cluster.
	createBody := map[string]any{
		"name":     "vault-prod",
		"scope":    "cluster",
		"targets":  map[string]any{"clusterIds": []string{"cluster:1", "cluster:2"}},
		"provider": vaultProvider(),
	}
	code, body := itDo(t, srv, http.MethodPost, "/api/v1/tenants/acme/secret-stores", "admin", createBody)
	if code != http.StatusOK {
		t.Fatalf("create: %d %s", code, body)
	}
	var created struct {
		Store types.SecretStore `json:"store"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	st := created.Store
	if st.ID == "" || st.Name != "vault-prod" || st.OrgID != "org:1" || st.Scope != "cluster" {
		t.Fatalf("unexpected store: %+v", st)
	}
	cmds := commandIDs(t, database)
	// Command IDs are nonce-suffixed per mutation: secretstore:{id}:{cluster}:{nonce}.
	wantPrefixes := []string{
		fmt.Sprintf("secretstore:%s:cluster:1:", st.ID),
		fmt.Sprintf("secretstore:%s:cluster:2:", st.ID),
	}
	if len(cmds) != 2 {
		t.Fatalf("fan-out commands = %v, want 2 commands", cmds)
	}
	for i, prefix := range wantPrefixes {
		if !strings.HasPrefix(cmds[i], prefix) {
			t.Fatalf("fan-out command %d = %q, want prefix %q", i, cmds[i], prefix)
		}
	}

	// Duplicate name conflicts.
	code, _ = itDo(t, srv, http.MethodPost, "/api/v1/tenants/acme/secret-stores", "admin", createBody)
	if code != http.StatusConflict {
		t.Fatalf("duplicate create: %d, want 409", code)
	}

	// List + get.
	code, body = itDo(t, srv, http.MethodGet, "/api/v1/tenants/acme/secret-stores", "viewer", nil)
	if code != http.StatusOK || !bytes.Contains([]byte(body), []byte("vault-prod")) {
		t.Fatalf("list: %d %s", code, body)
	}
	code, body = itDo(t, srv, http.MethodGet, "/api/v1/tenants/acme/secret-stores/vault-prod", "viewer", nil)
	if code != http.StatusOK {
		t.Fatalf("get: %d %s", code, body)
	}

	// Status: pending until both clusters ack.
	code, body = itDo(t, srv, http.MethodGet, "/api/v1/tenants/acme/secret-stores/vault-prod/status", "viewer", nil)
	if code != http.StatusOK {
		t.Fatalf("status: %d %s", code, body)
	}
	var st1 struct {
		Status types.SecretStoreStatus `json:"status"`
	}
	if err := json.Unmarshal([]byte(body), &st1); err != nil {
		t.Fatal(err)
	}
	if st1.Status.Delivered || len(st1.Status.Conditions) != 2 {
		t.Fatalf("status before ack: %+v", st1.Status)
	}
	if _, err := database.Pool.Exec(ctx,
		`UPDATE agent_commands SET status = 'acked', result_message = 'applied'`); err != nil {
		t.Fatal(err)
	}
	code, body = itDo(t, srv, http.MethodGet, "/api/v1/tenants/acme/secret-stores/vault-prod/status", "viewer", nil)
	if code != http.StatusOK {
		t.Fatalf("status after ack: %d %s", code, body)
	}
	var st2 struct {
		Status types.SecretStoreStatus `json:"status"`
	}
	if err := json.Unmarshal([]byte(body), &st2); err != nil {
		t.Fatal(err)
	}
	if !st2.Status.Delivered {
		t.Fatalf("status after ack: %+v", st2.Status)
	}

	// Patch: retarget to cluster:1 only.
	code, body = itDo(t, srv, http.MethodPatch, "/api/v1/tenants/acme/secret-stores/vault-prod", "admin",
		map[string]any{"targets": map[string]any{"clusterIds": []string{"cluster:1"}}})
	if code != http.StatusOK {
		t.Fatalf("patch: %d %s", code, body)
	}

	// Delete: fans out a delete command, then 404 on get.
	code, _ = itDo(t, srv, http.MethodDelete, "/api/v1/tenants/acme/secret-stores/vault-prod", "admin", nil)
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if code, _ = itDo(t, srv, http.MethodGet, "/api/v1/tenants/acme/secret-stores/vault-prod", "viewer", nil); code != http.StatusNotFound {
		t.Fatalf("get after delete: %d, want 404", code)
	}
	var delCount int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM agent_commands WHERE type = $1`, types.AgentCommandSecretStoreDelete).Scan(&delCount); err != nil {
		t.Fatal(err)
	}
	if delCount != 1 {
		t.Fatalf("delete fan-out = %d, want 1 (retargeted to cluster:1)", delCount)
	}

	// Audit rows for create/update/delete.
	var auditCount int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE object_id = $1 AND action LIKE 'secretstore.%'`, st.ID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 3 {
		t.Fatalf("audit rows = %d, want 3 (created, updated, deleted)", auditCount)
	}
}

// TestSecretStoreAuthz covers the authz ladder: no token 401, outsider 403,
// viewer 403 on writes, and the platform-scope superuser gate.
func TestSecretStoreAuthz(t *testing.T) {
	srv, _ := itServer(t)
	defer srv.Close()

	if code, _ := itDo(t, srv, http.MethodGet, "/api/v1/tenants/acme/secret-stores", "", nil); code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", code)
	}
	if code, _ := itDo(t, srv, http.MethodGet, "/api/v1/tenants/acme/secret-stores", "outsider", nil); code != http.StatusForbidden {
		t.Errorf("outsider list: %d, want 403", code)
	}
	write := map[string]any{
		"name":     "vault-x",
		"scope":    "cluster",
		"targets":  map[string]any{"clusterIds": []string{"cluster:1"}},
		"provider": vaultProvider(),
	}
	if code, _ := itDo(t, srv, http.MethodPost, "/api/v1/tenants/acme/secret-stores", "viewer", write); code != http.StatusForbidden {
		t.Errorf("viewer write: %d, want 403", code)
	}

	// Platform scope requires platform superuser even for the org admin...
	// "admin" is a superuser here; a non-superuser org admin must be denied.
	// itAuthorizer grants admin org:1 admin + platform superuser, so the
	// platform write succeeds and the store is visible read-only to tenants.
	platformWrite := map[string]any{
		"name":     "inari-platform",
		"scope":    "platform",
		"targets":  map[string]any{"clusterIds": []string{"cluster:1"}},
		"provider": vaultProvider(),
	}
	if code, body := itDo(t, srv, http.MethodPost, "/api/v1/tenants/acme/secret-stores", "admin", platformWrite); code != http.StatusOK {
		t.Fatalf("superuser platform create: %d %s", code, body)
	}
	// Viewer can read the platform store.
	if code, _ := itDo(t, srv, http.MethodGet, "/api/v1/tenants/acme/secret-stores/inari-platform", "viewer", nil); code != http.StatusOK {
		t.Errorf("viewer read platform store: %d, want 200", code)
	}
	// Viewer cannot patch/delete it (org admin gate fires first).
	if code, _ := itDo(t, srv, http.MethodPatch, "/api/v1/tenants/acme/secret-stores/inari-platform", "viewer",
		map[string]any{"targets": map[string]any{"clusterIds": []string{"cluster:2"}}}); code != http.StatusForbidden {
		t.Errorf("viewer patch platform store: %d, want 403", code)
	}
	if code, _ := itDo(t, srv, http.MethodDelete, "/api/v1/tenants/acme/secret-stores/inari-platform", "viewer", nil); code != http.StatusForbidden {
		t.Errorf("viewer delete platform store: %d, want 403", code)
	}

	// Non-superuser org admin: platform create and platform-store writes are
	// gated by superuser on platform:inari, not org admin.
	if code, _ := itDo(t, srv, http.MethodPost, "/api/v1/tenants/acme/secret-stores", "orgadmin", platformWrite); code != http.StatusForbidden {
		t.Errorf("orgadmin platform create: %d, want 403", code)
	}
	if code, _ := itDo(t, srv, http.MethodPatch, "/api/v1/tenants/acme/secret-stores/inari-platform", "orgadmin",
		map[string]any{"targets": map[string]any{"clusterIds": []string{"cluster:2"}}}); code != http.StatusForbidden {
		t.Errorf("orgadmin patch platform store: %d, want 403", code)
	}
	if code, _ := itDo(t, srv, http.MethodDelete, "/api/v1/tenants/acme/secret-stores/inari-platform", "orgadmin", nil); code != http.StatusForbidden {
		t.Errorf("orgadmin delete platform store: %d, want 403", code)
	}

	// Validation: invalid provider → 422.
	bad := map[string]any{
		"name":     "bad",
		"scope":    "cluster",
		"targets":  map[string]any{"clusterIds": []string{"cluster:1"}},
		"provider": map[string]any{"vault": map[string]any{"authSecretRef": map[string]any{"name": "", "namespace": ""}}},
	}
	if code, _ := itDo(t, srv, http.MethodPost, "/api/v1/tenants/acme/secret-stores", "admin", bad); code != http.StatusUnprocessableEntity {
		t.Errorf("invalid provider: %d, want 422", code)
	}

	// Tenant isolation: explicit clusterIds must belong to the org, or the
	// fan-out would enqueue commands into another tenant's agent queue.
	foreign := map[string]any{
		"name":     "vault-foreign",
		"scope":    "cluster",
		"targets":  map[string]any{"clusterIds": []string{"cluster:9"}},
		"provider": vaultProvider(),
	}
	if code, body := itDo(t, srv, http.MethodPost, "/api/v1/tenants/acme/secret-stores", "admin", foreign); code != http.StatusUnprocessableEntity {
		t.Errorf("foreign cluster target: %d, want 422 (%s)", code, body)
	}
}

// TestSecretStoreSetTargets verifies clusterSetRef fan-out resolves through
// the SetResolver seam.
func TestSecretStoreSetTargets(t *testing.T) {
	srv, database := itServer(t)
	defer srv.Close()

	code, body := itDo(t, srv, http.MethodPost, "/api/v1/tenants/acme/secret-stores", "admin",
		map[string]any{
			"name":     "vault-set",
			"scope":    "cluster",
			"targets":  map[string]any{"clusterSetRef": "prod"},
			"provider": vaultProvider(),
		})
	if code != http.StatusOK {
		t.Fatalf("create with set ref: %d %s", code, body)
	}
	var created struct {
		Store types.SecretStore `json:"store"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	cmds := commandIDs(t, database)
	wantPrefix := fmt.Sprintf("secretstore:%s:cluster:1:", created.Store.ID)
	if len(cmds) != 1 || !strings.HasPrefix(cmds[0], wantPrefix) {
		t.Fatalf("set fan-out = %v, want one command with prefix %s (env=prod only)", cmds, wantPrefix)
	}
}
