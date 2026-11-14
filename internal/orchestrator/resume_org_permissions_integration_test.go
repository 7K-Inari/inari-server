//go:build integration

package orchestrator_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/eventbus/eventbustest"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
)

type resumePermissionCheck struct {
	subject  string
	relation string
	object   string
}

type mutableResumeAuthorizer struct {
	allowed atomic.Bool
	calls   atomic.Int32
	last    atomic.Value
}

func (a *mutableResumeAuthorizer) Check(_ context.Context, subject, relation, object string) (bool, error) {
	a.calls.Add(1)
	a.last.Store(resumePermissionCheck{subject: subject, relation: relation, object: object})
	return a.allowed.Load(), nil
}

func (a *mutableResumeAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func (a *mutableResumeAuthorizer) lastCheck() resumePermissionCheck {
	value := a.last.Load()
	if value == nil {
		return resumePermissionCheck{}
	}
	return value.(resumePermissionCheck)
}

type resumeSideEffects struct {
	files      map[string]string
	prs        int
	deletions  int
	commands   int
	instances  int
	instanceDB string
}

func captureResumeSideEffects(t *testing.T, database *db.DB, git *gitprovider.Fake, queue *itQueue) resumeSideEffects {
	t.Helper()
	out := resumeSideEffects{
		files: git.Files("inari-dev/acme-inari-state", "main"), prs: len(git.PRs),
		deletions: len(git.Deletions), commands: len(queue.cmds),
	}
	if err := database.Pool.QueryRow(context.Background(), `SELECT count(*),
		COALESCE(string_agg(id || ':' || version || ':' || spec::text || ':' || state::text, ',' ORDER BY id), '')
		FROM resource_instances`).Scan(&out.instances, &out.instanceDB); err != nil {
		t.Fatal(err)
	}
	return out
}

func approvalIDFromResponse(t *testing.T, body string) string {
	t.Helper()
	var out struct {
		Deploy orchestrator.DeployResult `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Deploy.Status != "pending_approval" || out.Deploy.ApprovalID == "" {
		t.Fatalf("expected pending approval, got %+v", out.Deploy)
	}
	return out.Deploy.ApprovalID
}

func gatedResumeApproval(t *testing.T, operation string, srv *httptest.Server, database *db.DB) string {
	t.Helper()
	ctx := context.Background()
	request := func(method, path, body string) string {
		t.Helper()
		code, response := itReq(t, srv, method, path, "good", body)
		if code != http.StatusOK {
			t.Fatalf("%s %s = %d %s", method, path, code, response)
		}
		return response
	}
	if operation == "deploy" {
		if _, err := database.Pool.Exec(ctx, `UPDATE catalog_items SET approval_policy='peer' WHERE id='curated:web-service'`); err != nil {
			t.Fatal(err)
		}
		return approvalIDFromResponse(t, request(http.MethodPost, "/api/v1/tenants/acme/deploys",
			`{"itemId":"curated:web-service","version":"0.1.0","clusterId":"cluster-1","name":"web","spec":{"hostname":"app.example.com"}}`))
	}

	if code, body := itReq(t, srv, http.MethodPut, "/api/v1/tenants/acme/catalog/curated:postgres-aws/pin", "good", `{"version":"1.0.0"}`); code >= 300 {
		t.Fatalf("pin postgres: %d %s", code, body)
	}
	request(http.MethodPost, "/api/v1/tenants/acme/deploys",
		`{"itemId":"curated:postgres-aws","clusterId":"cluster-1","name":"db1","spec":{"storageGB":20}}`)
	if operation == "rollback" {
		request(http.MethodPost, "/api/v1/tenants/acme/instances/db1/upgrade", `{"toVersion":"1.1.0"}`)
	}
	if _, err := database.Pool.Exec(ctx, `UPDATE catalog_items SET approval_policy='peer' WHERE id='curated:postgres-aws'`); err != nil {
		t.Fatal(err)
	}
	switch operation {
	case "update":
		return approvalIDFromResponse(t, request(http.MethodPatch, "/api/v1/tenants/acme/instances/db1", `{"spec":{"storageGB":42}}`))
	case "upgrade":
		return approvalIDFromResponse(t, request(http.MethodPost, "/api/v1/tenants/acme/instances/db1/upgrade", `{"toVersion":"1.1.0"}`))
	case "rollback":
		return approvalIDFromResponse(t, request(http.MethodPost, "/api/v1/tenants/acme/instances/db1/rollback", `{"toVersion":"1.0.0"}`))
	case "delete":
		return approvalIDFromResponse(t, request(http.MethodDelete, "/api/v1/tenants/acme/instances/db1", ""))
	default:
		t.Fatalf("unknown resume operation %q", operation)
		return ""
	}
}

func TestApprovalResumeRequiresOrgDeploymentPermission(t *testing.T) {
	for _, operation := range []string{"deploy", "update", "upgrade", "rollback", "delete"} {
		t.Run(operation, func(t *testing.T) {
			permissions := &mutableResumeAuthorizer{}
			permissions.allowed.Store(true)
			// The target resolver remains allowed: only the independent org
			// deployments.create permission is revoked after the request.
			srv, database, git, queue, _, dispatcher := itServerM3Targets(t, nil, &stubTargetResolver{}, permissions)
			defer srv.Close()
			ctx := context.Background()
			approvalID := gatedResumeApproval(t, operation, srv, database)
			before := captureResumeSideEffects(t, database, git, queue)

			permissions.allowed.Store(false)
			code, body := itReq(t, srv, http.MethodPost, "/api/v1/tenants/acme/approvals/"+approvalID+"/decide", "peer", `{"approve":true}`)
			if code != http.StatusOK {
				t.Fatalf("approve: %d %s", code, body)
			}
			if err := eventbustest.DispatchOnce(ctx, dispatcher); err != nil {
				t.Fatalf("terminal permission denial must not retry: %v", err)
			}

			after := captureResumeSideEffects(t, database, git, queue)
			if !reflect.DeepEqual(after, before) {
				t.Errorf("revoked org permission had resume side effects:\nbefore: %+v\nafter:  %+v", before, after)
			}
			var deniedAudits int
			if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='deploy.target_denied'`).Scan(&deniedAudits); err != nil {
				t.Fatal(err)
			}
			if deniedAudits != 1 {
				t.Errorf("terminal denial audits = %d, want 1", deniedAudits)
			}
			if calls := permissions.calls.Load(); calls != 1 {
				t.Errorf("org permission checks = %d, want 1", calls)
			}
			wantCheck := resumePermissionCheck{subject: "user:user-1", relation: authz.RelationDeploymentsCreate, object: authz.OrgObject("org:1")}
			if got := permissions.lastCheck(); got != wantCheck {
				t.Errorf("org permission check = %+v, want %+v", got, wantCheck)
			}
		})
	}
}
