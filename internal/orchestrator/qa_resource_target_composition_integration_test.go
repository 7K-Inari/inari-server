//go:build integration

package orchestrator_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/eventbus/eventbustest"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
	"github.com/7K-Inari/inari-server/internal/types"
)

type qaLazyTargetResolver struct {
	svc atomic.Pointer[resourcetargets.Service]
}

func (r *qaLazyTargetResolver) ResolveResource(ctx context.Context, orgID, subject, capability string, action resourcetargets.Action,
	ref resourcetargets.TargetResourceRef, selection json.RawMessage) (*resourcetargets.ResolvedTarget, error) {
	svc := r.svc.Load()
	if svc == nil {
		return nil, fmt.Errorf("QA resolver used before initialization")
	}
	return svc.ResolveResource(ctx, orgID, subject, capability, action, ref, selection)
}

type qaDeploymentAuthorizer struct{ allow bool }

func (a *qaDeploymentAuthorizer) Check(_ context.Context, _, relation, _ string) (bool, error) {
	if relation == authz.RelationResourceTargetsManage {
		return false, nil
	}
	return a.allow, nil
}
func (a *qaDeploymentAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type qaDeploymentClusters struct{}

func (qaDeploymentClusters) GetCluster(ctx context.Context, id string) (*types.Cluster, error) {
	return (itClusters{}).GetCluster(ctx, id)
}
func (qaDeploymentClusters) ListClusters(_ context.Context, orgID string) ([]types.Cluster, error) {
	if orgID != "org:1" {
		return nil, nil
	}
	return []types.Cluster{{ID: "cluster-1", OrgID: orgID, Name: "kind-dev", State: types.ClusterStateActive}}, nil
}

type qaDeploymentInventory struct{}

func (qaDeploymentInventory) BaselineRepoSelector(context.Context, db.Querier, string, string) (string, error) {
	return "", nil
}
func (qaDeploymentInventory) GetGitRepo(context.Context, db.Querier, string, string) (*types.TenantGitRepo, error) {
	return nil, inventory.ErrRepoNotFound
}
func (qaDeploymentInventory) ListClusterBaselineRepos(context.Context, db.Querier, string) (map[string]*types.TenantGitRepo, error) {
	return map[string]*types.TenantGitRepo{}, nil
}
func (qaDeploymentInventory) ListClusterAddons(context.Context, db.Querier, string, string) ([]*types.ClusterAddon, error) {
	return nil, nil
}

type qaDeploymentCapabilities struct{}

func (qaDeploymentCapabilities) List(context.Context, db.Querier, string) ([]types.Capability, error) {
	return nil, nil
}
func (qaDeploymentCapabilities) ListForOrg(context.Context, db.Querier, string) ([]types.Capability, error) {
	return nil, nil
}

type qaDeploymentTeams struct{ id string }

func (t qaDeploymentTeams) ListTeams(context.Context, string) ([]types.Team, error) {
	return []types.Team{{ID: t.id}}, nil
}

type qaDeploymentEnvironment struct {
	srv        *httptest.Server
	database   *db.DB
	git        *gitprovider.Fake
	queue      *itQueue
	dispatcher *audit.Dispatcher
	targets    *resourcetargets.Service
	targetID   string
	teamID     string
}

func newQADeploymentEnvironment(t *testing.T) *qaDeploymentEnvironment {
	t.Helper()
	lazy := &qaLazyTargetResolver{}
	srv, database, git, queue, _, dispatcher := itServerM3Targets(t, nil, lazy)
	ctx := context.Background()
	var roleID string
	if err := database.Pool.QueryRow(ctx, `SELECT id FROM roles WHERE org_id='org:1' AND name='editor'`).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	var teamID string
	if err := database.Pool.QueryRow(ctx, `INSERT INTO teams (org_id, name, role_id, keycloak_group_path)
		VALUES ('org:1', 'qa-deployers', $1, '/tenant-acme/qa-deployers') RETURNING id`, roleID).Scan(&teamID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `UPDATE memberships SET team_id=$1 WHERE org_id='org:1' AND user_id='user-1'`, teamID); err != nil {
		t.Fatal(err)
	}
	authorizer := &qaDeploymentAuthorizer{allow: true}
	targets := resourcetargets.NewService(database, resourcetargets.NewStore(), resourcetargets.DefaultRegistry(), authorizer, audit.NewStore(),
		resourcetargets.Sources{
			Clusters: qaDeploymentClusters{}, Inventory: qaDeploymentInventory{}, Capabilities: qaDeploymentCapabilities{}, Teams: qaDeploymentTeams{id: teamID},
		})
	lazy.svc.Store(targets)
	target, err := targets.Create(ctx, "org:1", "user:admin", resourcetargets.CreateInput{
		Name: "deployment", ResourceRef: resourcetargets.TargetResourceRef{Kind: resourcetargets.ResourceKindCluster, ID: "cluster-1"},
		Capability: resourcetargets.CapabilityDeploymentCluster, Config: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targets.SetGrant(ctx, "org:1", target.ID, teamID, resourcetargets.ActionUse, "user:admin"); err != nil {
		t.Fatal(err)
	}
	return &qaDeploymentEnvironment{
		srv: srv, database: database, git: git, queue: queue, dispatcher: dispatcher,
		targets: targets, targetID: target.ID, teamID: teamID,
	}
}

func (e *qaDeploymentEnvironment) requestApproval(t *testing.T) string {
	t.Helper()
	if _, err := e.database.Pool.Exec(context.Background(), `UPDATE catalog_items SET approval_policy='peer' WHERE id='core/web-service'`); err != nil {
		t.Fatal(err)
	}
	code, body := itReq(t, e.srv, http.MethodPost, "/api/v1/tenants/acme/deploys", "good",
		`{"itemId":"core/web-service","version":"0.1.0","clusterId":"cluster-1","name":"web","spec":{"hostname":"app.example.com"}}`)
	if code != http.StatusOK {
		t.Fatalf("request deployment approval = %d %s", code, body)
	}
	return approvalIDFromResponse(t, body)
}

func (e *qaDeploymentEnvironment) approveAndDispatch(t *testing.T, approvalID string) {
	t.Helper()
	code, body := itReq(t, e.srv, http.MethodPost, "/api/v1/tenants/acme/approvals/"+approvalID+"/decide", "peer", `{"approve":true}`)
	if code != http.StatusOK {
		t.Fatalf("approve deployment = %d %s", code, body)
	}
	if err := eventbustest.DispatchOnce(context.Background(), e.dispatcher); err != nil {
		t.Fatal(err)
	}
}

func TestQARealResolverDeploymentApprovalResume(t *testing.T) {
	env := newQADeploymentEnvironment(t)
	defer env.srv.Close()
	approvalID := env.requestApproval(t)
	env.approveAndDispatch(t, approvalID)

	var instances int
	if err := env.database.Pool.QueryRow(context.Background(), `SELECT count(*) FROM resource_instances`).Scan(&instances); err != nil {
		t.Fatal(err)
	}
	if instances != 1 || len(env.git.Files("inari-dev/acme-inari-state", "main")) == 0 || len(env.queue.cmds) == 0 {
		t.Fatalf("real resolver approval resume did not apply deployment: instances=%d git=%v commands=%d",
			instances, env.git.Files("inari-dev/acme-inari-state", "main"), len(env.queue.cmds))
	}
}

func TestQARealResolverApprovalResumeRevocation(t *testing.T) {
	for _, revocation := range []string{"grant", "membership"} {
		t.Run(revocation, func(t *testing.T) {
			env := newQADeploymentEnvironment(t)
			defer env.srv.Close()
			approvalID := env.requestApproval(t)
			ctx := context.Background()
			switch revocation {
			case "grant":
				if err := env.targets.RevokeGrant(ctx, "org:1", env.targetID, env.teamID, "user:admin"); err != nil {
					t.Fatal(err)
				}
			case "membership":
				if _, err := env.database.Pool.Exec(ctx, `DELETE FROM memberships WHERE org_id='org:1' AND user_id='user-1'`); err != nil {
					t.Fatal(err)
				}
			}
			env.approveAndDispatch(t, approvalID)

			var instances, denied int
			if err := env.database.Pool.QueryRow(ctx, `SELECT count(*) FROM resource_instances`).Scan(&instances); err != nil {
				t.Fatal(err)
			}
			if err := env.database.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='deploy.target_denied'`).Scan(&denied); err != nil {
				t.Fatal(err)
			}
			if instances != 0 || len(env.git.Files("inari-dev/acme-inari-state", "main")) != 0 || len(env.queue.cmds) != 0 || denied != 1 {
				t.Fatalf("%s revocation had side effects or missed audit: instances=%d git=%v commands=%d denied=%d",
					revocation, instances, env.git.Files("inari-dev/acme-inari-state", "main"), len(env.queue.cmds), denied)
			}
		})
	}
}
