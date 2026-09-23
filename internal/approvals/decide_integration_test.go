//go:build integration

package approvals

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/types"
)

// decideRoles resolves org roles per subject for the decide harness.
type decideRoles map[string]types.Role

func (r decideRoles) RoleOf(_ context.Context, _, userID string) (types.Role, error) {
	return r[userID], nil
}

type decideItems struct{ item *types.CatalogItem }

func (d decideItems) GetItemByID(context.Context, string) (*types.CatalogItem, error) {
	return d.item, nil
}

// itDecideServer wires the full decide authorization chain: FGA authorizer
// (also the platform checker), DB-backed role resolver, and item resolver.
func itDecideServer(t *testing.T, az itAuthorizer, roles RoleResolver, items ItemResolver) (*httptest.Server, *db.DB) {
	t.Helper()
	database := itDB(t)
	if _, err := database.Pool.Exec(context.Background(),
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES
		 ('org:1','acme','Acme','kc-1'), ('org:3','other','Other','kc-3')`); err != nil {
		t.Fatal(err)
	}
	svc := NewService(database, NewStore(database), audit.NewStore(), roles, items).WithPlatformChecker(az)
	h := NewHandler(svc, itTenants{
		"acme":  {ID: "org:1", Slug: "acme"},
		"other": {ID: "org:3", Slug: "other"},
	}, az, roles)
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	h.RegisterRoutes(api)
	return httptest.NewServer(router), database
}

func itDecide(t *testing.T, srv *httptest.Server, org, id, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/tenants/"+org+"/approvals/"+id+"/decide",
		bytes.NewReader([]byte(`{"approve":true}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	return resp.StatusCode, b.String()
}

// itSeedRequest inserts an approval request with an explicit requester and
// action ("" = catalog approval). Returns the generated id.
func itSeedRequest(t *testing.T, database *db.DB, orgID, itemID, action, requester string) string {
	t.Helper()
	var id string
	err := database.Pool.QueryRow(context.Background(),
		`INSERT INTO approval_requests (org_id, item_id, version, cluster_id, spec, requester, action, name, expires_at)
		 VALUES ($1, NULLIF($2, ''), '', '', '{}', $3, $4, 'req', $5) RETURNING id`,
		orgID, itemID, requester, action, time.Now().Add(time.Hour)).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestDecideLifecycleFrozenOrg reproduces issue #74: once a tenant deletion
// is requested, the org's FGA tuples are swept, so decide must authorize via
// the platform org_creator check or the DB-backed org role.
func TestDecideLifecycleFrozenOrg(t *testing.T) {
	denyAll := itAuthorizer{allow: map[string]bool{}}
	platformOnly := itAuthorizer{allow: map[string]bool{authz.ObjectPlatform: true}}

	t.Run("org-admin approves via DB role after the FGA sweep", func(t *testing.T) {
		srv, database := itDecideServer(t, denyAll, decideRoles{"user-3": types.RoleOrgAdmin}, nil)
		defer srv.Close()
		id := itSeedRequest(t, database, "org:1", "", types.ApprovalActionTenantDecommission, "user:req-1")
		code, body := itDecide(t, srv, "acme", id, "acme-only")
		if code != http.StatusOK {
			t.Fatalf("org-admin decide = %d: %s", code, body)
		}
		var out struct {
			Approval types.ApprovalRequest `json:"approval"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
		if out.Approval.State != types.ApprovalStateApproved {
			t.Errorf("state = %q, want approved", out.Approval.State)
		}
	})

	t.Run("platform-admin approves via org_creator", func(t *testing.T) {
		var seen []string
		az := itAuthorizer{allow: platformOnly.allow, seen: &seen}
		srv, database := itDecideServer(t, az, decideRoles{}, nil)
		defer srv.Close()
		id := itSeedRequest(t, database, "org:1", "", types.ApprovalActionTenantDecommission, "user:req-1")
		// "outsider" (user-2) is not a member of acme and holds no org role.
		code, body := itDecide(t, srv, "acme", id, "outsider")
		if code != http.StatusOK {
			t.Fatalf("platform-admin decide = %d: %s", code, body)
		}
		want := authz.RelationOrgCreator + " " + authz.ObjectPlatform
		for _, s := range seen {
			if s == want {
				return
			}
		}
		t.Errorf("platform check %q never observed; seen = %v", want, seen)
	})

	t.Run("developer role is denied even after the sweep", func(t *testing.T) {
		srv, database := itDecideServer(t, denyAll, decideRoles{"user-3": types.RoleDeveloper}, nil)
		defer srv.Close()
		id := itSeedRequest(t, database, "org:1", "", types.ApprovalActionTenantDecommission, "user:req-1")
		if code, body := itDecide(t, srv, "acme", id, "acme-only"); code != http.StatusForbidden {
			t.Fatalf("developer decide = %d: %s, want 403", code, body)
		}
	})

	t.Run("outsider with no grant anywhere is denied", func(t *testing.T) {
		srv, database := itDecideServer(t, denyAll, decideRoles{}, nil)
		defer srv.Close()
		id := itSeedRequest(t, database, "org:1", "", types.ApprovalActionTenantDecommission, "user:req-1")
		if code, body := itDecide(t, srv, "acme", id, "outsider"); code != http.StatusForbidden {
			t.Fatalf("outsider decide = %d: %s, want 403", code, body)
		}
	})

	t.Run("requester cannot self-decide even as org_creator", func(t *testing.T) {
		srv, database := itDecideServer(t, platformOnly, decideRoles{}, nil)
		defer srv.Close()
		id := itSeedRequest(t, database, "org:1", "", types.ApprovalActionTenantDecommission, "user:user-2")
		if code, body := itDecide(t, srv, "acme", id, "outsider"); code != http.StatusForbidden {
			t.Fatalf("self-decide = %d: %s, want 403", code, body)
		}
	})

	t.Run("platform-engineer approves via DB role after the sweep", func(t *testing.T) {
		srv, database := itDecideServer(t, denyAll, decideRoles{"user-3": types.RolePlatformEngineer}, nil)
		defer srv.Close()
		id := itSeedRequest(t, database, "org:1", "", types.ApprovalActionTenantDecommission, "user:req-1")
		if code, body := itDecide(t, srv, "acme", id, "acme-only"); code != http.StatusOK {
			t.Fatalf("platform-engineer decide = %d: %s", code, body)
		}
	})

	t.Run("viewer is denied at the handler floor after the sweep", func(t *testing.T) {
		srv, database := itDecideServer(t, denyAll, decideRoles{"user-3": types.RoleViewer}, nil)
		defer srv.Close()
		id := itSeedRequest(t, database, "org:1", "", types.ApprovalActionTenantDecommission, "user:req-1")
		if code, body := itDecide(t, srv, "acme", id, "acme-only"); code != http.StatusForbidden {
			t.Fatalf("viewer decide = %d: %s, want 403", code, body)
		}
	})

	t.Run("second decide on the same approval conflicts", func(t *testing.T) {
		srv, database := itDecideServer(t, denyAll, decideRoles{"user-3": types.RoleOrgAdmin}, nil)
		defer srv.Close()
		id := itSeedRequest(t, database, "org:1", "", types.ApprovalActionTenantDecommission, "user:req-1")
		if code, body := itDecide(t, srv, "acme", id, "acme-only"); code != http.StatusOK {
			t.Fatalf("first decide = %d: %s", code, body)
		}
		if code, body := itDecide(t, srv, "acme", id, "acme-only"); code != http.StatusConflict {
			t.Fatalf("second decide = %d: %s, want 409", code, body)
		}
	})

	t.Run("unauthenticated decide is rejected", func(t *testing.T) {
		srv, database := itDecideServer(t, denyAll, decideRoles{"user-3": types.RoleOrgAdmin}, nil)
		defer srv.Close()
		id := itSeedRequest(t, database, "org:1", "", types.ApprovalActionTenantDecommission, "user:req-1")
		if code, _ := itDecide(t, srv, "acme", id, ""); code != http.StatusUnauthorized {
			t.Fatalf("no-token decide = %d, want 401", code)
		}
		if code, _ := itDecide(t, srv, "acme", id, "bogus"); code != http.StatusUnauthorized {
			t.Fatalf("bad-token decide = %d, want 401", code)
		}
	})
}

// TestDecideCatalogPlatformAdminPolicy covers the non-frozen path: an
// org-admin approves a catalog request under the platform-admin policy.
func TestDecideCatalogPlatformAdminPolicy(t *testing.T) {
	az := itAuthorizer{allow: map[string]bool{"organization:1": true}}
	items := decideItems{item: &types.CatalogItem{ID: "curated:postgres-aws", ApprovalPolicy: types.ApprovalPolicyPlatformAdmin}}
	srv, database := itDecideServer(t, az, decideRoles{"user-3": types.RoleOrgAdmin}, items)
	defer srv.Close()
	if _, err := database.Pool.Exec(context.Background(),
		`INSERT INTO catalog_items (id, source, name) VALUES ('curated:postgres-aws', 'curated', 'postgres-aws')`); err != nil {
		t.Fatal(err)
	}
	id := itSeedRequest(t, database, "org:1", "curated:postgres-aws", "", "user:req-1")
	code, body := itDecide(t, srv, "acme", id, "acme-only")
	if code != http.StatusOK {
		t.Fatalf("org-admin catalog decide = %d: %s", code, body)
	}
	var out struct {
		Approval types.ApprovalRequest `json:"approval"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Approval.State != types.ApprovalStateApproved {
		t.Errorf("state = %q, want approved", out.Approval.State)
	}
}
