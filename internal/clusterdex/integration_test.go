//go:build integration

// Full-flow integration test for the Dex fan-out (operator sunset Phase 2):
// outbox events drive the reconciler over real Postgres (cluster registry,
// teams/roles join, baseline bindings), fake git, and a capture queue
// standing in for the agent.
package clusterdex

import (
	"context"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

type itFixture struct {
	svc        *Service
	reconciler *Reconciler
	git        *gitprovider.Fake
	queue      *captureQueue
}

func newIT(t *testing.T) *itFixture {
	t.Helper()
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	seed := `
		INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1');
		INSERT INTO roles (org_id, name, display_name, builtin, permissions) VALUES
		  ('org:1','admin','Admin',true,'["tenant.read"]'),
		  ('org:1','operator','Platform Engineer',true,'["tenant.read"]'),
		  ('org:1','viewer','Viewer',true,'["tenant.read"]');
		INSERT INTO teams (org_id, name, role_id, keycloak_group_path) SELECT 'org:1','org-admins',id,'/tenant-acme/org-admins' FROM roles WHERE org_id='org:1' AND name='admin';
		INSERT INTO teams (org_id, name, role_id, keycloak_group_path) SELECT 'org:1','platform-team',id,'/tenant-acme/platform-team' FROM roles WHERE org_id='org:1' AND name='operator';
		INSERT INTO teams (org_id, name, role_id, keycloak_group_path) SELECT 'org:1','viewers',id,'/tenant-acme/viewers' FROM roles WHERE org_id='org:1' AND name='viewer';
		INSERT INTO clusters (id, org_id, name, labels, state) VALUES
		  ('c1','org:1','prod-eu','{"env":"prod"}','active'),
		  ('c2','org:1','prod-us','{"env":"prod"}','active');
		INSERT INTO tenant_git_repos (id, org_id, name, repo, scope, commit_policy, base_branch, is_default)
		  VALUES ('repo-1','org:1','baseline','acme/acme-inari-state','platform','direct','main',true);`
	if _, err := database.Pool.Exec(ctx, seed); err != nil {
		t.Fatal(err)
	}

	auditStore := audit.NewStore()
	invStore := inventory.NewStore()
	registry := clusterregistry.NewService(database, nil, clusterregistry.NewStore(), auditStore, 0, false)
	tenants := tenancy.NewService(database, nil, tenancy.NewStore(), auditStore)
	fake := gitprovider.NewFake()
	if _, err := fake.EnsureRepo(ctx, "acme/acme-inari-state"); err != nil {
		t.Fatal(err)
	}
	queue := &captureQueue{}
	resolver := gitprovider.NewRepoResolver(repoStoreAdapter{invStore, database}, nil, gitprovider.StaticResolver{P: fake})
	svc := NewService(database, testConfig(), registry, tenants, invStore, invStore, resolver, queue, auditStore, nil)
	return &itFixture{svc: svc, reconciler: NewReconciler(svc, nil, nil), git: fake, queue: queue}
}

// repoStoreAdapter binds inventory.Store to gitprovider.RepoStore (mirrors
// main.go).
type repoStoreAdapter struct {
	store *inventory.Store
	db    *db.DB
}

func (a repoStoreAdapter) GetGitRepo(ctx context.Context, orgID, id string) (*types.TenantGitRepo, error) {
	return a.store.GetGitRepo(ctx, a.db.Pool, orgID, id)
}

func (a repoStoreAdapter) GetDefaultGitRepo(ctx context.Context, orgID string) (*types.TenantGitRepo, error) {
	return a.store.GetDefaultGitRepo(ctx, a.db.Pool, orgID)
}

func clusterEvent(t *testing.T, eventType, clusterID, name string) *types.OutboxEvent {
	t.Helper()
	return outboxEvent(t, "org:1", eventType, types.ClusterPayload{OrgID: "org:1", ClusterID: clusterID, Name: name})
}

func TestDexFanoutEndToEnd(t *testing.T) {
	f := newIT(t)
	ctx := context.Background()

	// 1. Cluster registration triggers the render: both appsets committed,
	//    per-cluster overlays present, registrations delivered per cluster.
	if err := f.reconciler.Handle(ctx, clusterEvent(t, types.EventClusterRegistered, "c1", "prod-eu")); err != nil {
		t.Fatal(err)
	}
	files := f.git.Files("acme/acme-inari-state", "main")
	for _, path := range []string{
		"dex/applicationset.yaml", "dex/values.yaml",
		"argocd-config/applicationset.yaml", "argocd-config/values.yaml",
		"clusters/prod-eu/dex/values.yaml", "clusters/prod-eu/argocd-config/values.yaml",
		"clusters/prod-us/dex/values.yaml", "clusters/prod-us/argocd-config/values.yaml",
	} {
		if files[path] == "" {
			t.Errorf("missing committed file %s (have %v)", path, keysOf(files))
		}
	}
	// Team-derived RBAC: org-admins (admin role) -> admin, platform-team +
	// viewers -> readonly. Fail-closed default preserved.
	argoOv := files["clusters/prod-eu/argocd-config/values.yaml"]
	if !strings.Contains(argoOv, "- /tenant-acme/org-admins") {
		t.Errorf("adminGroups must contain org-admins:\n%s", argoOv)
	}
	if !strings.Contains(argoOv, "- /tenant-acme/platform-team") || !strings.Contains(argoOv, "- /tenant-acme/viewers") {
		t.Errorf("viewerGroups must contain platform-team + viewers:\n%s", argoOv)
	}
	if !strings.Contains(argoOv, `policyDefault: ""`) {
		t.Errorf("fail-closed policyDefault missing:\n%s", argoOv)
	}
	if len(f.queue.cmds) != 4 {
		t.Fatalf("commands = %d, want 4 (2 clusters x 2 appsets)", len(f.queue.cmds))
	}

	// 2. Label change (re-registration): opt prod-us out.
	if _, err := f.svc.db.Pool.Exec(ctx,
		`UPDATE clusters SET labels = '{"env":"prod","inari.io/dex":"disabled"}' WHERE id = 'c2'`); err != nil {
		t.Fatal(err)
	}
	if err := f.reconciler.Handle(ctx, clusterEvent(t, types.EventClusterRegistered, "c2", "prod-us")); err != nil {
		t.Fatal(err)
	}
	files = f.git.Files("acme/acme-inari-state", "main")
	dexSet := files["dex/applicationset.yaml"]
	if strings.Contains(dexSet, "prod-us") || !strings.Contains(dexSet, "prod-eu") {
		t.Errorf("opted-out cluster must leave the elements list:\n%s", dexSet)
	}
	if files["clusters/prod-us/dex/values.yaml"] != "" {
		t.Error("opted-out cluster overlays must be purged")
	}
	// Drain delivery: prod-us receives the empty view.
	var drained bool
	for _, cmd := range f.queue.cmds {
		if cmd.ClusterID == "c2" && strings.Contains(bridgeManifest(t, cmd), "elements: []") {
			drained = true
		}
	}
	if !drained {
		t.Error("no empty-view drain delivery for the opted-out cluster")
	}

	// 3. Team role change (rbac.mappings.updated): demote org-admins to
	//    viewer -> the group moves to the readonly list.
	if _, err := f.svc.db.Pool.Exec(ctx,
		`UPDATE teams SET role_id = (SELECT id FROM roles WHERE org_id='org:1' AND name='viewer')
		 WHERE org_id='org:1' AND name='org-admins'`); err != nil {
		t.Fatal(err)
	}
	if err := f.reconciler.Handle(ctx, outboxEvent(t, "org:1", types.EventRBACMappingsUpdated,
		types.RBACMappingsPayload{OrgID: "org:1"})); err != nil {
		t.Fatal(err)
	}
	argoOv = f.git.Files("acme/acme-inari-state", "main")["clusters/prod-eu/argocd-config/values.yaml"]
	if strings.Contains(argoOv, "adminGroups:\n    - /tenant-acme/org-admins") {
		t.Errorf("demoted team must leave adminGroups:\n%s", argoOv)
	}
	if !strings.Contains(argoOv, "- /tenant-acme/org-admins") {
		t.Errorf("demoted team must land in viewerGroups:\n%s", argoOv)
	}

	// 4. Cluster deletion drains the fleet: empty appsets, overlays purged.
	if _, err := f.svc.db.Pool.Exec(ctx, `DELETE FROM clusters WHERE id = 'c1'`); err != nil {
		t.Fatal(err)
	}
	if err := f.reconciler.Handle(ctx, clusterEvent(t, types.EventClusterDeleted, "c1", "prod-eu")); err != nil {
		t.Fatal(err)
	}
	files = f.git.Files("acme/acme-inari-state", "main")
	if !strings.Contains(files["dex/applicationset.yaml"], "elements: []") {
		t.Errorf("appset must drain to empty elements:\n%s", files["dex/applicationset.yaml"])
	}
	for p := range files {
		if strings.HasPrefix(p, "clusters/") {
			t.Errorf("stale overlay survived deletion: %s", p)
		}
	}
}
