//go:build integration

package orchestrator_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/7K-Inari/inari-server/internal/eventbus/eventbustest"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
)

type stubTargetResolver struct{ deny atomic.Bool }

func (s *stubTargetResolver) ResolveResource(ctx context.Context, orgID, subject, capability string, action resourcetargets.Action,
	ref resourcetargets.ResourceRef, selection json.RawMessage) (*resourcetargets.ResolvedTarget, error) {
	if s.deny.Load() {
		return nil, resourcetargets.ErrTargetDenied
	}
	cluster, err := (itClusters{}).GetCluster(ctx, ref.ID)
	if err != nil {
		return nil, err
	}
	return &resourcetargets.ResolvedTarget{Cluster: cluster}, nil
}

func TestDeployRequiresCurrentTargetGrant(t *testing.T) {
	targets := &stubTargetResolver{}
	targets.deny.Store(true)
	srv, database, git, queue, _, _ := itServerM3Targets(t, nil, targets)
	defer srv.Close()
	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "good",
		`{"itemId":"curated:postgres-aws","clusterId":"cluster-1","name":"denied","spec":{"engineVersion":"16"}}`)
	if code != http.StatusForbidden {
		t.Fatalf("deploy without target grant = %d %s, want 403", code, body)
	}
	var instances int
	if err := database.Pool.QueryRow(context.Background(), `SELECT count(*) FROM resource_instances`).Scan(&instances); err != nil {
		t.Fatal(err)
	}
	if instances != 0 || len(git.Files("inari-dev/acme-inari-state", "main")) != 0 || len(queue.cmds) != 0 {
		t.Errorf("denied deploy had side effects: instances=%d git=%v commands=%d", instances, git.Files("inari-dev/acme-inari-state", "main"), len(queue.cmds))
	}
}

func TestApprovalResumeRevalidatesOriginalRequesterTargetGrant(t *testing.T) {
	targets := &stubTargetResolver{}
	srv, database, git, queue, _, dispatcher := itServerM3Targets(t, nil, targets)
	defer srv.Close()
	ctx := context.Background()
	if _, err := database.Pool.Exec(ctx, `UPDATE catalog_items SET approval_policy='peer' WHERE id='curated:web-service'`); err != nil {
		t.Fatal(err)
	}
	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "good",
		`{"itemId":"curated:web-service","clusterId":"cluster-1","name":"web","channel":"incubating","spec":{"hostname":"app.example.com"}}`)
	if code != http.StatusOK {
		t.Fatalf("request approval: %d %s", code, body)
	}
	var out struct {
		Deploy orchestrator.DeployResult `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Deploy.ApprovalID == "" {
		t.Fatalf("expected approval ID: %+v", out.Deploy)
	}
	// Revoke after request but before approval. Resume must use the stored
	// original requester, not the system automation actor, for the target PEP.
	targets.deny.Store(true)
	code, body = itReq(t, srv, "POST", "/api/v1/tenants/acme/approvals/"+out.Deploy.ApprovalID+"/decide", "peer", `{"approve":true}`)
	if code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, body)
	}
	if err := eventbustest.DispatchOnce(ctx, dispatcher); err != nil {
		t.Fatal(err)
	}
	var instances, deniedAudits int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM resource_instances`).Scan(&instances); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='deploy.target_denied'`).Scan(&deniedAudits); err != nil {
		t.Fatal(err)
	}
	if instances != 0 || len(git.Files("inari-dev/acme-inari-state", "main")) != 0 || len(queue.cmds) != 0 {
		t.Errorf("revoked approval resume had side effects: instances=%d git=%v commands=%d", instances, git.Files("inari-dev/acme-inari-state", "main"), len(queue.cmds))
	}
	if deniedAudits != 1 {
		t.Errorf("target denial audits = %d, want 1", deniedAudits)
	}
}
