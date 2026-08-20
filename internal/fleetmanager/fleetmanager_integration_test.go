//go:build integration

package fleetmanager_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/fleetmanager"
	"github.com/7K-Inari/inari-server/internal/types"
)

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

type itQueue struct{ cmds []types.AgentCommand }

func (q *itQueue) Enqueue(_ context.Context, cmd *types.AgentCommand) error {
	q.cmds = append(q.cmds, *cmd)
	return nil
}

type itGates struct{ requests []*types.ApprovalRequest }

func (g *itGates) RequestLifecycleApproval(_ context.Context, in approvals.LifecycleApprovalInput) (*types.ApprovalRequest, error) {
	req := &types.ApprovalRequest{ID: "approval:test", OrgID: in.OrgID, Action: in.Action, Spec: in.Context, State: types.ApprovalStatePending}
	g.requests = append(g.requests, req)
	return req, nil
}

func itSetup(t *testing.T) (*fleetmanager.Service, *itQueue, *itGates, *db.DB) {
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
	seed := `
		INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1');
		INSERT INTO clusters (id, org_id, name, state, labels) VALUES
		  ('cluster:1','org:1','canary-1','active','{"env":"canary"}'),
		  ('cluster:2','org:1','canary-2','active','{"env":"canary"}'),
		  ('cluster:3','org:1','prod-1','active','{"env":"prod"}'),
		  ('cluster:4','org:1','prod-2','active','{"env":"prod"}');`
	if _, err := database.Pool.Exec(ctx, seed); err != nil {
		t.Fatal(err)
	}
	queue := &itQueue{}
	clusters := &itClusters{clusters: []types.Cluster{
		{ID: "cluster:1", OrgID: "org:1", Labels: map[string]string{"env": "canary"}},
		{ID: "cluster:2", OrgID: "org:1", Labels: map[string]string{"env": "canary"}},
		{ID: "cluster:3", OrgID: "org:1", Labels: map[string]string{"env": "prod"}},
		{ID: "cluster:4", OrgID: "org:1", Labels: map[string]string{"env": "prod"}},
	}}
	gates := &itGates{}
	svc := fleetmanager.NewService(database, fleetmanager.NewStore(), audit.NewStore(), clusters, queue).
		WithGateRequester(gates)
	return svc, queue, gates, database
}

func ackCommand(t *testing.T, database *db.DB, cmdID string, status types.CommandStatus) {
	t.Helper()
	// Rollout health gating reads agent_commands; the queue rows are written
	// by the real gateway queue in production, so mirror one here.
	_, err := database.Pool.Exec(context.Background(),
		`INSERT INTO agent_commands (id, cluster_id, type, payload, status) VALUES ($1,'cluster:x','t','{}',$2)
		 ON CONFLICT (id) DO UPDATE SET status = $2`, cmdID, status)
	if err != nil {
		t.Fatal(err)
	}
}

func TestStagedRolloutWithApprovalGate(t *testing.T) {
	svc, queue, gates, database := itSetup(t)
	ctx := context.Background()

	canary, err := svc.CreateClusterSet(ctx, "user-1", "org:1", "canary", map[string]string{"env": "canary"})
	if err != nil {
		t.Fatal(err)
	}
	prod, err := svc.CreateClusterSet(ctx, "user-1", "org:1", "prod", map[string]string{"env": "prod"})
	if err != nil {
		t.Fatal(err)
	}

	r, err := svc.CreateRollout(ctx, "user-1", "org:1", fleetmanager.CreateRolloutInput{
		Name: "agent-upgrade", Kind: types.RolloutKindAgentUpgrade, DesiredVersion: "v1.6.0",
		Stages: []types.RolloutStage{
			{Name: "canary", ClusterSetIDs: []string{canary.ID}, MaxConcurrency: "50%"},
			{Name: "wave", ClusterSetIDs: []string{prod.ID}, MaxConcurrency: "100%",
				BeforeGate: &types.RolloutStageGate{Type: "approval"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.State != types.RolloutStatePending {
		t.Fatalf("state = %q", r.State)
	}

	r, err = svc.StartRollout(ctx, "user-1", "org:1", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	// 50% of 2 canary clusters → first batch delivers to exactly 1.
	if len(queue.cmds) != 1 {
		t.Fatalf("commands after start = %d, want 1 (concurrency bound)", len(queue.cmds))
	}
	if r.State != types.RolloutStateRunning {
		t.Fatalf("state = %q", r.State)
	}

	// Ack the first command: health gate passes, second canary cluster is delivered.
	ackCommand(t, database, queue.cmds[0].ID, types.CommandStatusAcked)
	if _, err := svc.AdvanceSweep(ctx); err != nil {
		t.Fatal(err)
	}
	if len(queue.cmds) != 2 {
		t.Fatalf("commands = %d, want 2 after first ack", len(queue.cmds))
	}

	// Ack the second: canary stage completes → before-gate of the wave stage
	// parks the rollout in waiting_gate with an approval request.
	ackCommand(t, database, queue.cmds[1].ID, types.CommandStatusAcked)
	if _, err := svc.AdvanceSweep(ctx); err != nil {
		t.Fatal(err)
	}
	r, _ = svc.GetRollout(ctx, "org:1", r.ID)
	if r.State != types.RolloutStateWaitingGate {
		t.Fatalf("state = %q, want waiting_gate", r.State)
	}
	if len(gates.requests) != 1 {
		t.Fatalf("approval requests = %d, want 1", len(gates.requests))
	}
	if len(queue.cmds) != 2 {
		t.Fatalf("no wave commands before approval, got %d", len(queue.cmds))
	}

	// Approve the gate via the resume path: wave stage fans out to both prod clusters.
	resume := fleetmanager.NewResumeHandler(svc, gateLoader{gates.requests[0]}, nil)
	payload, _ := json.Marshal(types.ApprovalPayload{
		OrgID: "org:1", ApprovalID: "approval:test", State: types.ApprovalStateApproved,
	})
	if err := resume.Handle(ctx, &types.OutboxEvent{EventType: types.EventApprovalDecided, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AdvanceSweep(ctx); err != nil {
		t.Fatal(err)
	}
	if len(queue.cmds) != 4 {
		t.Fatalf("commands = %d, want 4 after gate approval", len(queue.cmds))
	}

	// Ack the wave: rollout completes.
	ackCommand(t, database, queue.cmds[2].ID, types.CommandStatusAcked)
	ackCommand(t, database, queue.cmds[3].ID, types.CommandStatusAcked)
	if _, err := svc.AdvanceSweep(ctx); err != nil {
		t.Fatal(err)
	}
	r, _ = svc.GetRollout(ctx, "org:1", r.ID)
	if r.State != types.RolloutStateCompleted {
		t.Fatalf("state = %q, want completed", r.State)
	}

	// Rollback to the current desired version is rejected: its command IDs
	// would collide with the apply commands and be silently deduped.
	if _, err := svc.Rollback(ctx, "user-1", "org:1", r.ID, "v1.6.0"); err == nil {
		t.Fatal("expected rollback-to-desired-version rejection")
	}

	// Rollback to the previous version: reverse-order rollback commands.
	before := len(queue.cmds)
	r, err = svc.Rollback(ctx, "user-1", "org:1", r.ID, "v1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if r.State != types.RolloutStateRolledBack {
		t.Fatalf("state = %q, want rolled_back", r.State)
	}
	if len(queue.cmds) != before+4 {
		t.Fatalf("rollback commands = %d, want %d", len(queue.cmds)-before, 4)
	}
}
type gateLoader struct{ req *types.ApprovalRequest }

func (g gateLoader) Get(context.Context, string, string) (*types.ApprovalRequest, error) {
	return g.req, nil
}

func TestGateRejectedWhilePaused(t *testing.T) {
	svc, _, gates, _ := itSetup(t)
	ctx := context.Background()

	canary, err := svc.CreateClusterSet(ctx, "user-1", "org:1", "canary", map[string]string{"env": "canary"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.CreateRollout(ctx, "user-1", "org:1", fleetmanager.CreateRolloutInput{
		Name: "gated", Kind: types.RolloutKindPolicyPack, TargetRef: "policypack:1", DesiredVersion: "1.0.0",
		Stages: []types.RolloutStage{{Name: "canary", ClusterSetIDs: []string{canary.ID}, MaxConcurrency: "2",
			BeforeGate: &types.RolloutStageGate{Type: "approval"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err = svc.StartRollout(ctx, "user-1", "org:1", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r.State != types.RolloutStateWaitingGate {
		t.Fatalf("state = %q, want waiting_gate", r.State)
	}
	if len(gates.requests) != 1 {
		t.Fatalf("approval requests = %d, want 1", len(gates.requests))
	}

	// Pause while parked on the gate, then the approval is rejected: the
	// rollout must fail, not resume into an already-decided gate forever.
	if _, err := svc.StopRollout(ctx, "user-1", "org:1", r.ID); err != nil {
		t.Fatal(err)
	}
	resume := fleetmanager.NewResumeHandler(svc, gateLoader{gates.requests[0]}, nil)
	payload, _ := json.Marshal(types.ApprovalPayload{
		OrgID: "org:1", ApprovalID: "approval:test", State: types.ApprovalStateRejected,
	})
	if err := resume.Handle(ctx, &types.OutboxEvent{EventType: types.EventApprovalDecided, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	r, _ = svc.GetRollout(ctx, "org:1", r.ID)
	if r.State != types.RolloutStateFailed {
		t.Fatalf("state = %q, want failed after gate rejection while paused", r.State)
	}
}

func TestRolloutStopResumeAndFailure(t *testing.T) {
	svc, queue, _, database := itSetup(t)
	ctx := context.Background()

	canary, err := svc.CreateClusterSet(ctx, "user-1", "org:1", "canary", map[string]string{"env": "canary"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.CreateRollout(ctx, "user-1", "org:1", fleetmanager.CreateRolloutInput{
		Name: "pack", Kind: types.RolloutKindPolicyPack, TargetRef: "policypack:1", DesiredVersion: "1.0.0",
		Stages: []types.RolloutStage{{Name: "canary", ClusterSetIDs: []string{canary.ID}, MaxConcurrency: "2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartRollout(ctx, "user-1", "org:1", r.ID); err != nil {
		t.Fatal(err)
	}
	if len(queue.cmds) != 2 {
		t.Fatalf("commands = %d, want 2", len(queue.cmds))
	}

	// Stop, then resume.
	if _, err := svc.StopRollout(ctx, "user-1", "org:1", r.ID); err != nil {
		t.Fatal(err)
	}
	r, _ = svc.GetRollout(ctx, "org:1", r.ID)
	if r.State != types.RolloutStatePaused {
		t.Fatalf("state = %q, want paused", r.State)
	}
	if _, err := svc.ResumeRollout(ctx, "user-1", "org:1", r.ID); err != nil {
		t.Fatal(err)
	}

	// A nacked target fails the rollout (health gate).
	ackCommand(t, database, queue.cmds[0].ID, types.CommandStatusNacked)
	if _, err := svc.AdvanceSweep(ctx); err != nil {
		t.Fatal(err)
	}
	r, _ = svc.GetRollout(ctx, "org:1", r.ID)
	if r.State != types.RolloutStateFailed {
		t.Fatalf("state = %q, want failed", r.State)
	}
}

func TestDriftSweepReportOnly(t *testing.T) {
	svc, _, _, database := itSetup(t)
	ctx := context.Background()

	if _, err := database.Pool.Exec(ctx, `
		INSERT INTO resource_instances (id, org_id, cluster_id, catalog_item_id, version, spec, resource_ref, state, sync_state)
		VALUES ('instance:1','org:1','cluster:1','item:1','1.0.0','{}',
		        '{"kind":"Deployment","name":"web","namespace":"default"}','running','OutOfSync')`); err != nil {
		t.Fatal(err)
	}

	n, err := svc.DriftSweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("new drift events = %d, want 1", n)
	}
	// Idempotent while open.
	n, err = svc.DriftSweep(ctx)
	if err != nil || n != 0 {
		t.Fatalf("second sweep = %d, %v; want 0 (deduped)", n, err)
	}

	events, err := svc.ListDrift(ctx, "org:1", "cluster:1", "open")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != types.DriftKindInstanceSpec {
		t.Fatalf("events = %+v", events)
	}
	if events[0].ResourceRef != "Deployment/default/web" {
		t.Errorf("resourceRef = %q", events[0].ResourceRef)
	}

	// Back in sync: the sweep resolves the open event.
	if _, err := database.Pool.Exec(ctx,
		`UPDATE resource_instances SET sync_state = 'Synced' WHERE id = 'instance:1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DriftSweep(ctx); err != nil {
		t.Fatal(err)
	}
	events, err = svc.ListDrift(ctx, "org:1", "cluster:1", "open")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("open events after resolution = %+v, want none", events)
	}
	resolved, err := svc.ListDrift(ctx, "org:1", "cluster:1", "resolved")
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 {
		t.Fatalf("resolved events = %+v, want 1", resolved)
	}
}

func TestAgentChannels(t *testing.T) {
	svc, _, _, _ := itSetup(t)
	ctx := context.Background()

	cs, err := svc.CreateClusterSet(ctx, "user-1", "org:1", "canary", map[string]string{"env": "canary"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetAgentChannel(ctx, "user-1", "org:1", cs.ID, types.AgentChannelCanary, "v1.6.0"); err != nil {
		t.Fatal(err)
	}
	// Upsert semantics on (set, channel).
	if _, err := svc.SetAgentChannel(ctx, "user-1", "org:1", cs.ID, types.AgentChannelCanary, "v1.6.1"); err != nil {
		t.Fatal(err)
	}
	channels, err := svc.ListAgentChannels(ctx, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if len(channels) != 1 || channels[0].DesiredAgentVersion != "v1.6.1" {
		t.Fatalf("channels = %+v", channels)
	}
	if _, err := svc.SetAgentChannel(ctx, "user-1", "org:1", cs.ID, "nightly", "v1.6.1"); err == nil {
		t.Error("expected channel validation error")
	}
}

func TestBulkOperations(t *testing.T) {
	svc, _, _, _ := itSetup(t)
	ctx := context.Background()

	clusters, err := svc.QueryClusters(ctx, "org:1", map[string]string{"env": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 2 {
		t.Fatalf("prod clusters = %d, want 2", len(clusters))
	}

	decider := &itDecider{}
	assigner := &itAssigner{}
	pinner := &itPinner{}
	svc.WithBulkSeams(decider, assigner, pinner)

	res, err := svc.BulkDecideApprovals(ctx, "org:1", "approver-1", []string{"a1", "a2"}, true, "batch")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || !res[0].OK || res[1].OK {
		t.Fatalf("results = %+v", res)
	}

	res, err = svc.BulkAssignPolicy(ctx, "user-1", "org:1", "policypack:1", []string{"clusterset:1", "clusterset:2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || !res[0].OK || !res[1].OK {
		t.Fatalf("results = %+v", res)
	}

	res, err = svc.BulkPinCatalog(ctx, "user-1", "org:1", []string{"item:1"}, "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || !res[0].OK {
		t.Fatalf("results = %+v", res)
	}
}

type itDecider struct{}

func (d *itDecider) Decide(_ context.Context, _, approvalID, _ string, _ bool, _ string) (*types.ApprovalRequest, error) {
	if approvalID == "a2" {
		return nil, context.DeadlineExceeded
	}
	return &types.ApprovalRequest{ID: approvalID}, nil
}

type itAssigner struct{}

func (a *itAssigner) Assign(_ context.Context, _, _, packID, _, targetID string) (*types.PolicyAssignment, error) {
	return &types.PolicyAssignment{PackID: packID, TargetID: targetID}, nil
}

type itPinner struct{}

func (p *itPinner) SetPin(_ context.Context, _, _, _, _ string) error { return nil }
