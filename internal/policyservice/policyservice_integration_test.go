//go:build integration

package policyservice_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/fleetmanager"
	"github.com/7K-Inari/inari-server/internal/policyservice"
	"github.com/7K-Inari/inari-server/internal/types"
)

type itClusters struct {
	clusters []types.Cluster
}

func (c *itClusters) ListClusters(_ context.Context, orgID string) ([]types.Cluster, error) {
	var out []types.Cluster
	for _, cl := range c.clusters {
		if cl.OrgID == orgID {
			out = append(out, cl)
		}
	}
	return out, nil
}

func (c *itClusters) GetCluster(_ context.Context, id string) (*types.Cluster, error) {
	for i := range c.clusters {
		if c.clusters[i].ID == id {
			return &c.clusters[i], nil
		}
	}
	return nil, errors.New("unknown cluster")
}

type itQueue struct{ cmds []types.AgentCommand }

func (q *itQueue) Enqueue(_ context.Context, cmd *types.AgentCommand) error {
	q.cmds = append(q.cmds, *cmd)
	return nil
}

const itDenyRego = `package inari.policy

deny contains {"rule": "disallowed-registry", "reason": "image not from approved registry", "remediation": "use registry.example.com"} if {
	input.spec.image != "registry.example.com/app"
}
`

func itService(t *testing.T) (*policyservice.Service, *itQueue, *db.DB) {
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
		  ('cluster:1','org:1','prod-eu','active','{"env":"prod"}'),
		  ('cluster:2','org:1','dev','active','{"env":"dev"}');`
	if _, err := database.Pool.Exec(ctx, seed); err != nil {
		t.Fatal(err)
	}
	queue := &itQueue{}
	clusters := &itClusters{clusters: []types.Cluster{
		{ID: "cluster:1", OrgID: "org:1", Name: "prod-eu", Labels: map[string]string{"env": "prod"}},
		{ID: "cluster:2", OrgID: "org:1", Name: "dev", Labels: map[string]string{"env": "dev"}},
	}}
	svc := policyservice.NewService(database, policyservice.NewStore(),
		policyservice.NewOPAEvaluator(), clusters, queue, audit.NewStore())
	fleet := fleetmanager.NewService(database, fleetmanager.NewStore(), audit.NewStore(), clusters, queue)
	svc.WithSetResolver(fleet)
	return svc, queue, database
}

func TestPolicyCRUD(t *testing.T) {
	svc, _, _ := itService(t)
	ctx := context.Background()

	p, err := svc.CreatePolicy(ctx, "user-1", "org:1", "registry", types.PolicyTargetRequest, types.PolicyEngineRego, itDenyRego)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" || p.Version != 1 || !p.Enabled {
		t.Fatalf("unexpected policy: %+v", p)
	}

	got, err := svc.GetPolicy(ctx, "org:1", p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "registry" {
		t.Fatalf("got %+v", got)
	}

	updated, err := svc.UpdatePolicy(ctx, "user-1", "org:1", p.ID, itDenyRego, false)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 2 || updated.Enabled {
		t.Fatalf("update did not bump version/disable: %+v", updated)
	}

	list, err := svc.ListPolicies(ctx, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list = %d, want 1", len(list))
	}

	if err := svc.DeletePolicy(ctx, "user-1", "org:1", p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetPolicy(ctx, "org:1", p.ID); !errors.Is(err, policyservice.ErrPolicyNotFound) {
		t.Fatalf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestPolicyCreateRejectsBrokenRego(t *testing.T) {
	svc, _, _ := itService(t)
	_, err := svc.CreatePolicy(context.Background(), "user-1", "org:1", "broken",
		types.PolicyTargetRequest, types.PolicyEngineRego, "package inari.policy\n\ndeny if {")
	if !errors.Is(err, policyservice.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestPreFlightBlocksAndExemptionAllows(t *testing.T) {
	svc, _, _ := itService(t)
	ctx := context.Background()

	p, err := svc.CreatePolicy(ctx, "user-1", "org:1", "registry", types.PolicyTargetRequest, types.PolicyEngineRego, itDenyRego)
	if err != nil {
		t.Fatal(err)
	}
	in := policyservice.PreFlightInput{
		OrgID: "org:1", ItemID: "item:1", Version: "1.0.0", ClusterID: "cluster:1",
		Spec:      json.RawMessage(`{"image":"evil.io/app"}`),
		Requester: "user-1",
	}
	decision, err := svc.PreFlight(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow {
		t.Fatalf("expected deny, got %+v", decision)
	}
	if len(decision.Violations) != 1 {
		t.Fatalf("violations = %+v", decision.Violations)
	}
	v := decision.Violations[0]
	if v.Rule != "disallowed-registry" || v.Reason == "" || v.Remediation == "" || v.Exempted {
		t.Fatalf("unexpected violation: %+v", v)
	}

	// Pending exemption does not waive.
	ex, err := svc.RequestExemption(ctx, "user-1", "org:1", p.ID, nil, "migration window", time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if decision, _ := svc.PreFlight(ctx, in); decision.Allow {
		t.Fatal("pending exemption must not waive")
	}

	if _, err := svc.DecideExemption(ctx, "user-2", "org:1", ex.ID, true); err != nil {
		t.Fatal(err)
	}
	decision, err = svc.PreFlight(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allow {
		t.Fatalf("approved exemption should allow, got %+v", decision)
	}
	if !decision.Violations[0].Exempted {
		t.Fatalf("violation should be marked exempted: %+v", decision.Violations[0])
	}

	// Second decision on the same exemption must conflict.
	if _, err := svc.DecideExemption(ctx, "user-2", "org:1", ex.ID, false); !errors.Is(err, policyservice.ErrExemptionNotPending) {
		t.Fatalf("expected ErrExemptionNotPending, got %v", err)
	}
}

func TestAssignDistributesApplyBundle(t *testing.T) {
	svc, queue, database := itService(t)
	ctx := context.Background()

	// Distribution is outbox-driven: Assign commits the assignment + event,
	// the dispatcher fan-out enqueues ApplyBundle commands.
	dispatcher := audit.NewDispatcher(database, time.Millisecond,
		policyservice.NewDistributeHandler(svc, slog.Default()))

	manifests := json.RawMessage(`[{"apiVersion":"kyverno.io/v1","kind":"ClusterPolicy","metadata":{"name":"require-labels"}}]`)
	pack, err := svc.CreatePolicyPack(ctx, "user-1", "org:1", "baseline", types.PolicyPackEngineKyverno, "", "1.0.0", nil, manifests)
	if err != nil {
		t.Fatal(err)
	}

	a, err := svc.Assign(ctx, "user-1", "org:1", pack.ID, types.PolicyTargetCluster, "cluster:1")
	if err != nil {
		t.Fatal(err)
	}
	if a.State != "active" {
		t.Fatalf("assignment = %+v", a)
	}
	if err := dispatcher.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}

	if len(queue.cmds) != 1 {
		t.Fatalf("commands = %d, want 1", len(queue.cmds))
	}
	cmd := queue.cmds[0]
	wantID := "apply-bundle:policypack:" + pack.ID + ":cluster:1"
	if cmd.ID != wantID {
		t.Fatalf("command ID = %q, want %q", cmd.ID, wantID)
	}
	if cmd.ClusterID != "cluster:1" {
		t.Fatalf("command cluster = %q", cmd.ClusterID)
	}

	// Duplicate assignment conflicts.
	if _, err := svc.Assign(ctx, "user-1", "org:1", pack.ID, types.PolicyTargetCluster, "cluster:1"); !errors.Is(err, policyservice.ErrAssignmentExists) {
		t.Fatalf("expected ErrAssignmentExists, got %v", err)
	}

	// Cluster set target resolves member clusters by selector (ClusterSets are
	// owned by the Fleet Manager since M4; wired via the SetResolver seam).
	fleet := fleetmanager.NewService(database, fleetmanager.NewStore(), audit.NewStore(),
		&itClusters{clusters: []types.Cluster{
			{ID: "cluster:1", OrgID: "org:1", Name: "prod-eu", Labels: map[string]string{"env": "prod"}},
			{ID: "cluster:2", OrgID: "org:1", Name: "dev", Labels: map[string]string{"env": "dev"}},
		}}, queue)
	cs, err := fleet.CreateClusterSet(ctx, "user-1", "org:1", "prod", map[string]string{"env": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Assign(ctx, "user-1", "org:1", pack.ID, types.PolicyTargetClusterSet, cs.ID); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(queue.cmds) != 2 {
		t.Fatalf("commands = %d, want 2 (cluster:1 via set)", len(queue.cmds))
	}
}

func TestListAssignments(t *testing.T) {
	svc, _, _ := itService(t)
	ctx := context.Background()

	manifests := json.RawMessage(`[{"apiVersion":"kyverno.io/v1","kind":"ClusterPolicy","metadata":{"name":"require-labels"}}]`)
	pack, err := svc.CreatePolicyPack(ctx, "user-1", "org:1", "baseline", types.PolicyPackEngineKyverno, "", "1.0.0", nil, manifests)
	if err != nil {
		t.Fatal(err)
	}

	// Unknown pack and cross-org access are 404-shaped.
	if _, err := svc.ListAssignments(ctx, "org:1", "policypack:missing"); !errors.Is(err, policyservice.ErrPackNotFound) {
		t.Fatalf("expected ErrPackNotFound, got %v", err)
	}
	if _, err := svc.ListAssignments(ctx, "org:2", pack.ID); !errors.Is(err, policyservice.ErrPackNotFound) {
		t.Fatalf("cross-org: expected ErrPackNotFound, got %v", err)
	}

	a, err := svc.Assign(ctx, "user-1", "org:1", pack.ID, types.PolicyTargetCluster, "cluster:1")
	if err != nil {
		t.Fatal(err)
	}
	list, err := svc.ListAssignments(ctx, "org:1", pack.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("assignments = %+v, want 1", list)
	}
	got := list[0]
	if got.ID != a.ID || got.TargetType != types.PolicyTargetCluster || got.TargetID != "cluster:1" || got.CreatedAt.IsZero() {
		t.Fatalf("assignment = %+v", got)
	}
}

func TestDeletePolicyPack(t *testing.T) {
	svc, _, database := itService(t)
	ctx := context.Background()
	newPack := func(t *testing.T, name string) *types.PolicyPack {
		t.Helper()
		manifests := json.RawMessage(`[{"apiVersion":"kyverno.io/v1","kind":"ClusterPolicy","metadata":{"name":"require-labels"}}]`)
		pack, err := svc.CreatePolicyPack(ctx, "user-1", "org:1", name, types.PolicyPackEngineKyverno, "", "1.0.0", nil, manifests)
		if err != nil {
			t.Fatal(err)
		}
		return pack
	}

	t.Run("missing pack is not found", func(t *testing.T) {
		err := svc.DeletePolicyPack(ctx, "user-1", "org:1", "policypack:missing", true)
		if !errors.Is(err, policyservice.ErrPackNotFound) {
			t.Fatalf("expected ErrPackNotFound, got %v", err)
		}
	})

	t.Run("assigned pack conflicts without force", func(t *testing.T) {
		pack := newPack(t, "conflict")
		a, err := svc.Assign(ctx, "user-1", "org:1", pack.ID, types.PolicyTargetCluster, "cluster:1")
		if err != nil {
			t.Fatal(err)
		}
		err = svc.DeletePolicyPack(ctx, "user-1", "org:1", pack.ID, false)
		var depErr *policyservice.DependencyError
		if !errors.As(err, &depErr) {
			t.Fatalf("expected DependencyError, got %v", err)
		}
		if len(depErr.Assignments) != 1 || depErr.Assignments[0].ID != a.ID {
			t.Fatalf("DependencyError.Assignments = %+v", depErr.Assignments)
		}
		// Pack and assignment survive the refused delete.
		if _, err := svc.GetPolicyPack(ctx, "org:1", pack.ID); err != nil {
			t.Fatal(err)
		}
		if list, _ := svc.ListAssignments(ctx, "org:1", pack.ID); len(list) != 1 {
			t.Fatalf("assignments after refused delete = %+v", list)
		}
	})

	t.Run("force cascade-unassigns and deletes with outbox events", func(t *testing.T) {
		pack := newPack(t, "force")
		a1, err := svc.Assign(ctx, "user-1", "org:1", pack.ID, types.PolicyTargetCluster, "cluster:1")
		if err != nil {
			t.Fatal(err)
		}
		a2, err := svc.Assign(ctx, "user-1", "org:1", pack.ID, types.PolicyTargetCluster, "cluster:2")
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.DeletePolicyPack(ctx, "user-1", "org:1", pack.ID, true); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.GetPolicyPack(ctx, "org:1", pack.ID); !errors.Is(err, policyservice.ErrPackNotFound) {
			t.Fatalf("expected ErrPackNotFound after delete, got %v", err)
		}
		var count int
		if err := database.Pool.QueryRow(ctx,
			`SELECT count(*) FROM policy_assignments WHERE pack_id = $1`, pack.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("assignments left = %d, want 0", count)
		}
		// Outbox: one unassigned per assignment + one pack deleted.
		rows, err := database.Pool.Query(ctx,
			`SELECT event_type, payload FROM outbox WHERE org_id = 'org:1' AND event_type IN ($1,$2) ORDER BY occurred_at, id`,
			types.EventPolicyPackUnassigned, types.EventPolicyPackDeleted)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var unassigned, deleted int
		for rows.Next() {
			var typ string
			var payload []byte
			if err := rows.Scan(&typ, &payload); err != nil {
				t.Fatal(err)
			}
			switch typ {
			case types.EventPolicyPackUnassigned:
				unassigned++
				var p types.PolicyPackAssignedPayload
				if err := json.Unmarshal(payload, &p); err != nil {
					t.Fatal(err)
				}
				if p.PackID != pack.ID || (p.AssignmentID != a1.ID && p.AssignmentID != a2.ID) {
					t.Fatalf("unassigned payload = %+v", p)
				}
			case types.EventPolicyPackDeleted:
				deleted++
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if unassigned != 2 || deleted != 1 {
			t.Fatalf("outbox events: unassigned = %d, deleted = %d; want 2, 1", unassigned, deleted)
		}
		// Audit rows for both actions exist.
		if err := database.Pool.QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE object_id = $1 AND action IN ('policy_pack.unassigned','policy_pack.deleted')`, pack.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 3 {
			t.Fatalf("audit rows = %d, want 3 (2 unassigned + 1 deleted)", count)
		}
		// Re-delete is a 404-shaped not-found.
		if err := svc.DeletePolicyPack(ctx, "user-1", "org:1", pack.ID, true); !errors.Is(err, policyservice.ErrPackNotFound) {
			t.Fatalf("re-delete: expected ErrPackNotFound, got %v", err)
		}
	})

	t.Run("unassigned pack deletes cleanly without force", func(t *testing.T) {
		pack := newPack(t, "plain")
		if err := svc.DeletePolicyPack(ctx, "user-1", "org:1", pack.ID, false); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.GetPolicyPack(ctx, "org:1", pack.ID); !errors.Is(err, policyservice.ErrPackNotFound) {
			t.Fatalf("expected ErrPackNotFound after delete, got %v", err)
		}
	})

	t.Run("platform-global pack is not deletable by tenants", func(t *testing.T) {
		pack := newPack(t, "global")
		if _, err := database.Pool.Exec(ctx, `UPDATE policy_packs SET org_id = NULL WHERE id = $1`, pack.ID); err != nil {
			t.Fatal(err)
		}
		err := svc.DeletePolicyPack(ctx, "user-1", "org:1", pack.ID, true)
		if !errors.Is(err, policyservice.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput, got %v", err)
		}
	})
}
