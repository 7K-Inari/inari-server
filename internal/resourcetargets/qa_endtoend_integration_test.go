//go:build integration

package resourcetargets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
)

func TestQAManagerListFiltersUnsupportedActions(t *testing.T) {
	svc, _, az, teamID, _ := serviceFixture(t)
	ctx := context.Background()
	deployment, err := svc.Create(ctx, "org:store", "user:admin", CreateInput{
		Name: "deployment", ResourceRef: TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capability: CapabilityDeploymentCluster, Config: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	grafana, err := svc.Create(ctx, "org:store", "user:admin", CreateInput{
		Name: "grafana", ResourceRef: TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capability: CapabilityMonitoringGrafana,
		Config:     json.RawMessage(strings.Replace(string(validGrafanaConfig()), "team-1", teamID, 1)),
	})
	if err != nil {
		t.Fatal(err)
	}
	az.manager = true

	for _, tc := range []struct {
		name   string
		action Action
		wantID string
	}{
		{name: "use selects only deployment", action: ActionUse, wantID: deployment.ID},
		{name: "provision selects only Grafana", action: ActionProvision, wantID: grafana.ID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listed, err := svc.List(ctx, "org:store", "admin", ListFilter{Action: tc.action})
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != 1 || listed[0].ID != tc.wantID {
				t.Fatalf("action %s returned target IDs %v, want only %s", tc.action, targetIDsForQA(listed), tc.wantID)
			}
		})
	}

	// Even corrupted/legacy unsupported grants must not make a provider
	// selectable for an action outside its contract, for any subject type.
	az.manager = false
	if err := svc.store.SetGrant(ctx, svc.db.Pool, &Grant{TargetID: deployment.ID, TeamID: teamID, Relation: ActionProvision}); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.SetGrant(ctx, svc.db.Pool, &Grant{TargetID: grafana.ID, TeamID: teamID, Relation: ActionUse}); err != nil {
		t.Fatal(err)
	}
	az.allow("alice", deployment.ID, "provision")
	az.allow("alice", grafana.ID, "use")
	for _, action := range []Action{ActionUse, ActionProvision} {
		listed, err := svc.List(ctx, "org:store", "alice", ListFilter{Action: action})
		if err != nil {
			t.Fatal(err)
		}
		if len(listed) != 0 {
			t.Errorf("non-manager action %s returned provider-incompatible targets %v", action, targetIDsForQA(listed))
		}
	}
}

func TestQAManagerActionListOmitsDisabledTargets(t *testing.T) {
	svc, _, az, _, _ := serviceFixture(t)
	ctx := context.Background()
	target, err := svc.Create(ctx, "org:store", "user:admin", CreateInput{
		Name: "disabled deployment", ResourceRef: TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capability: CapabilityDeploymentCluster, Config: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled := false
	if _, err := svc.Update(ctx, target.OrgID, target.ID, "user:admin", PatchInput{Enabled: &enabled, Revision: target.Revision}); err != nil {
		t.Fatal(err)
	}
	az.manager = true

	listed, err := svc.List(ctx, target.OrgID, "admin", ListFilter{Action: ActionUse})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 0 {
		t.Fatalf("disabled target %s remained in use list", target.ID)
	}
	listed, err = svc.List(ctx, target.OrgID, "admin", ListFilter{Action: ActionView, IncludeUnavailable: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != target.ID || listed[0].Enabled {
		t.Fatalf("manager could not inspect disabled target: %+v", listed)
	}
	if _, err := svc.Resolve(ctx, ResolveInput{
		OrgID: target.OrgID, Subject: "admin", TargetID: target.ID, Action: ActionUse,
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("disabled target Resolve = %v, want ErrUnavailable", err)
	}
}

func TestQAMonitoringHTTPEndToEnd(t *testing.T) {
	svc, database, az, teamID, _ := serviceFixture(t)
	az.managerSubjects = map[string]bool{"user:admin": true}
	tenants := tenancy.NewService(database, nil, tenancy.NewStore(), nil)
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), targetValidator{}, database)
	NewHandler(svc, tenants, az).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	defer srv.Close()

	config := json.RawMessage(strings.Replace(string(validGrafanaConfig()), "team-1", teamID, 1))
	body, err := json.Marshal(map[string]any{
		"name": "Central Grafana", "resourceRef": TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		"capability": CapabilityMonitoringGrafana, "config": config,
	})
	if err != nil {
		t.Fatal(err)
	}
	code, raw := targetRequest(t, srv, http.MethodPost, "/api/v1/tenants/store/resource-targets", "admin", string(body))
	if code != http.StatusOK {
		t.Fatalf("register Grafana = %d %s", code, raw)
	}
	var created struct {
		Target Target `json:"target"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatal(err)
	}
	targetID := created.Target.ID
	if targetID == "" {
		t.Fatalf("registration returned no target ID: %s", raw)
	}
	if created.Target.Readiness.State != ReadinessReady || created.Target.Binding.BaselineRepoID != "repo-store" ||
		!slices.Equal(created.Target.EffectiveActions, []Action{ActionView, ActionProvision}) {
		t.Fatalf("registration returned an unresolved manager descriptor: %+v", created.Target)
	}

	code, raw = targetRequest(t, srv, http.MethodPut,
		"/api/v1/tenants/store/resource-targets/"+targetID+"/grants/"+teamID, "admin", `{"relation":"provision"}`)
	if code != http.StatusOK {
		t.Fatalf("set provision grant = %d %s", code, raw)
	}
	az.allow("alice", targetID, "viewer")
	az.allow("alice", targetID, "provision")

	code, raw = targetRequest(t, srv, http.MethodGet,
		"/api/v1/tenants/store/resource-targets?capability=monitoring.grafana&action=provision", "alice", "")
	if code != http.StatusOK || !strings.Contains(string(raw), targetID) || !strings.Contains(string(raw), `"state":"ready"`) {
		t.Fatalf("provision list = %d %s", code, raw)
	}
	code, raw = targetRequest(t, srv, http.MethodGet, "/api/v1/tenants/store/resource-targets/"+targetID, "alice", "")
	if code != http.StatusOK || !strings.Contains(string(raw), `"baselineRepoId":"repo-store"`) {
		t.Fatalf("Grafana get = %d %s", code, raw)
	}

	resolved, err := svc.Resolve(context.Background(), ResolveInput{
		OrgID: "org:store", Subject: "alice", TargetID: targetID, Capability: CapabilityMonitoringGrafana,
		Action: ActionProvision, ExpectedRevision: 1,
		Selection: json.RawMessage(`{"folder":"acme/team-a","datasource":"metrics","evaluation":"central"}`),
	})
	if err != nil {
		t.Fatalf("resolve registered Grafana target: %v", err)
	}
	if !resolved.Approval.Required || resolved.Target.Binding.BaselineRepoID != "repo-store" {
		t.Fatalf("resolved target = %+v", resolved)
	}
	for name, selection := range map[string]string{
		"outside folder": `{"folder":"other/team","datasource":"metrics","evaluation":"central"}`,
		"arbitrary URL":  `{"folder":"acme/team-a","datasource":"metrics","evaluation":"central","baseUrl":"https://evil.example"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.Resolve(context.Background(), ResolveInput{
				OrgID: "org:store", Subject: "alice", TargetID: targetID, Action: ActionProvision,
				Selection: json.RawMessage(selection),
			}); err == nil {
				t.Fatal("invalid selection resolved successfully")
			}
		})
	}
	if _, err := svc.Resolve(context.Background(), ResolveInput{
		OrgID: "org:store", Subject: "alice", TargetID: targetID, Action: ActionProvision, ExpectedRevision: 99,
		Selection: json.RawMessage(`{"folder":"acme/team-a","datasource":"metrics","evaluation":"central"}`),
	}); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale revision resolve = %v, want ErrStaleRevision", err)
	}

	code, raw = targetRequest(t, srv, http.MethodDelete,
		"/api/v1/tenants/store/resource-targets/"+targetID+"/grants/"+teamID, "admin", "")
	if code != http.StatusOK {
		t.Fatalf("revoke provision grant = %d %s", code, raw)
	}
	// Keep the fake OpenFGA allow in place: the current-DB grant fence must
	// independently reject the next submit after revocation.
	if _, err := svc.Resolve(context.Background(), ResolveInput{
		OrgID: "org:store", Subject: "alice", TargetID: targetID, Action: ActionProvision,
		Selection: json.RawMessage(`{"folder":"acme/team-a","datasource":"metrics","evaluation":"central"}`),
	}); !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("post-revocation resolve = %v, want ErrTargetDenied", err)
	}
}

type qaConcurrentManagerAuthorizer struct{}

func (qaConcurrentManagerAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (qaConcurrentManagerAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func TestQAConcurrentAdoptionAndPatch(t *testing.T) {
	svc, database, _, _, _ := serviceFixture(t)
	svc.authz = qaConcurrentManagerAuthorizer{}
	ctx := context.Background()
	const contenders = 6

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, contenders)
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.Create(ctx, "org:store", "user:admin", CreateInput{
				Name: "one overlay", ResourceRef: TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
				Capability: CapabilityDeploymentCluster, Config: json.RawMessage(`{}`),
			})
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	var successes, conflicts int
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent adoption error: %v", err)
		}
	}
	if successes != 1 || conflicts != contenders-1 {
		t.Fatalf("concurrent adoption successes=%d conflicts=%d, want 1/%d", successes, conflicts, contenders-1)
	}
	var count int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM resource_targets`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("concurrent adoption persisted %d targets, want one", count)
	}

	target, err := svc.store.Get(ctx, database.Pool, "org:store", "target-does-not-exist")
	if !errors.Is(err, ErrTargetNotFound) || target != nil {
		t.Fatalf("unknown target lookup = %+v, %v", target, err)
	}
	listed, err := svc.store.List(ctx, database.Pool, "org:store", CapabilityDeploymentCluster)
	if err != nil || len(listed) != 1 {
		t.Fatalf("stored targets = %+v, %v", listed, err)
	}
	target = listed[0]

	start = make(chan struct{})
	errs = make(chan error, contenders)
	for i := range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			name := fmt.Sprintf("rename-%d", i)
			_, err := svc.Update(ctx, target.OrgID, target.ID, "user:admin", PatchInput{Name: &name, Revision: 1})
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	successes, conflicts = 0, 0
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrStaleRevision):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent PATCH error: %v", err)
		}
	}
	if successes != 1 || conflicts != contenders-1 {
		t.Fatalf("concurrent PATCH successes=%d stale=%d, want 1/%d", successes, conflicts, contenders-1)
	}
}

func TestQAMutationResponsesContainComputedDescriptor(t *testing.T) {
	svc, _, az, teamID, _ := serviceFixture(t)
	az.manager = true
	ctx := context.Background()
	target, err := svc.Create(ctx, "org:store", "user:admin", CreateInput{
		Name: "deployment", ResourceRef: TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capability: CapabilityDeploymentCluster, Config: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertManagerDescriptor := func(stage string, descriptor *Target, revision int64) {
		t.Helper()
		if descriptor.Readiness.State != ReadinessReady || descriptor.Binding.BaselineRepoID != "repo-store" {
			t.Errorf("%s response has unresolved descriptor: readiness=%q binding=%+v", stage, descriptor.Readiness.State, descriptor.Binding)
		}
		if descriptor.Revision != revision || !slices.Equal(descriptor.EffectiveActions, []Action{ActionView, ActionUse}) {
			t.Errorf("%s response revision/actions = %d/%v, want %d/[view use]", stage, descriptor.Revision, descriptor.EffectiveActions, revision)
		}
	}
	assertManagerDescriptor("create", target, 1)
	if len(target.Grants) != 0 {
		t.Errorf("create response grants = %+v, want none", target.Grants)
	}
	if _, err := svc.SetGrant(ctx, target.OrgID, target.ID, teamID, ActionUse, "user:admin"); err != nil {
		t.Fatal(err)
	}
	name := "renamed"
	updated, err := svc.Update(ctx, target.OrgID, target.ID, "user:admin", PatchInput{Name: &name, Revision: target.Revision})
	if err != nil {
		t.Fatal(err)
	}
	assertManagerDescriptor("update", updated, 2)
	if len(updated.Grants) != 1 || updated.Grants[0].TeamID != teamID || updated.Grants[0].Relation != ActionUse {
		t.Errorf("update response manager grants = %+v, want the current use grant", updated.Grants)
	}
	got, err := svc.Get(ctx, updated.OrgID, "admin", updated.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Readiness.State != updated.Readiness.State || got.Binding != updated.Binding ||
		!slices.Equal(got.EffectiveActions, updated.EffectiveActions) || len(got.Grants) != len(updated.Grants) {
		t.Errorf("PATCH and GET descriptors disagree: PATCH=%+v GET=%+v", updated, got)
	}
	noOp, err := svc.Update(ctx, updated.OrgID, updated.ID, "user:admin", PatchInput{Revision: updated.Revision})
	if err != nil {
		t.Fatal(err)
	}
	assertManagerDescriptor("no-op update", noOp, 2)
	if len(noOp.Grants) != 1 {
		t.Errorf("no-op update response lost manager grants: %+v", noOp.Grants)
	}
}

func TestQAMutationDecorationUsesTransactionConnection(t *testing.T) {
	svc, database, az, teamID, _ := serviceFixture(t)
	az.manager = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config := database.Pool.Config()
	config.MaxConns = 1
	limited, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	original := database.Pool
	database.Pool = limited
	t.Cleanup(func() {
		database.Pool = original
		limited.Close()
	})

	target, err := svc.Create(ctx, "org:store", "user:admin", CreateInput{
		Name: "single connection", ResourceRef: TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capability: CapabilityDeploymentCluster, Config: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("create with one database connection: %v", err)
	}
	if _, err := svc.SetGrant(ctx, target.OrgID, target.ID, teamID, ActionUse, "user:admin"); err != nil {
		t.Fatal(err)
	}
	name := "still single connection"
	updated, err := svc.Update(ctx, target.OrgID, target.ID, "user:admin", PatchInput{Name: &name, Revision: target.Revision})
	if err != nil {
		t.Fatalf("update with one database connection: %v", err)
	}
	if len(updated.Grants) != 1 || updated.Grants[0].Relation != ActionUse {
		t.Fatalf("single-connection update grants = %+v", updated.Grants)
	}
}

func TestQADisabledMutationResponseIsComputed(t *testing.T) {
	svc, _, az, _, snapshot := serviceFixture(t)
	az.manager = true
	ctx := context.Background()
	target, err := svc.Create(ctx, "org:store", "user:admin", CreateInput{
		Name: "deployment", ResourceRef: TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capability: CapabilityDeploymentCluster, Config: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Cluster.State = "revoked"
	enabled := false
	updated, err := svc.Update(ctx, target.OrgID, target.ID, "user:admin", PatchInput{Enabled: &enabled, Revision: target.Revision})
	if err != nil {
		t.Fatalf("disable with stale evidence: %v", err)
	}
	if updated.Enabled || updated.Readiness.State != ReadinessUnavailable || updated.Binding.Renderer != RendererArgoCD {
		t.Fatalf("disabled response is not a computed unavailable descriptor: %+v", updated)
	}
	if !slices.Equal(updated.EffectiveActions, []Action{ActionView, ActionUse}) {
		t.Errorf("disabled manager response actions = %v", updated.EffectiveActions)
	}
}

const qaMutationCapability = "qa.mutation"

type qaMutationProvider struct{ resolveErr error }

func (p *qaMutationProvider) Describe() ProviderDescriptor {
	return ProviderDescriptor{
		Capability: qaMutationCapability, ResourceKinds: []string{ResourceKindCluster}, Actions: []Action{ActionView, ActionUse},
		ConfigSchema: json.RawMessage(`{"type":"object"}`), SelectionSchema: json.RawMessage(`{"type":"object"}`), UISchema: json.RawMessage(`{}`),
	}
}
func (p *qaMutationProvider) NormalizeConfig(raw json.RawMessage) (json.RawMessage, error) {
	return deploymentClusterProvider{}.NormalizeConfig(raw)
}
func (p *qaMutationProvider) ValidateRegistration(snapshot ResourceSnapshot, _ json.RawMessage) error {
	if snapshot.Cluster == nil {
		return invalid("resourceRef", "cluster does not exist")
	}
	return nil
}
func (p *qaMutationProvider) Resolve(target *Target, snapshot ResourceSnapshot) (Binding, Readiness, error) {
	if p.resolveErr != nil {
		return Binding{}, Readiness{}, p.resolveErr
	}
	return clusterBinding(snapshot), Readiness{State: ReadinessReady}, nil
}
func (p *qaMutationProvider) ValidateSelection(target *Target, selection json.RawMessage) (json.RawMessage, ApprovalPolicy, error) {
	return deploymentClusterProvider{}.ValidateSelection(target, selection)
}

func TestQAMutationDecorationFailureRollsBack(t *testing.T) {
	svc, database, az, _, _ := serviceFixture(t)
	az.manager = true
	ctx := context.Background()
	provider := &qaMutationProvider{}
	if err := svc.registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	resolveErr := errors.New("QA descriptor decoration failed")
	provider.resolveErr = resolveErr
	input := CreateInput{
		Name: "must roll back", ResourceRef: TargetResourceRef{Kind: ResourceKindCluster, ID: "cluster:store"},
		Capability: qaMutationCapability, Config: json.RawMessage(`{}`),
	}
	if _, err := svc.Create(ctx, "org:store", "user:admin", input); !errors.Is(err, resolveErr) {
		t.Fatalf("create decoration error = %v, want injected provider error", err)
	}
	var targets, audits, events int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM resource_targets WHERE capability=$1`, qaMutationCapability).Scan(&targets); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='resource_target.created'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE event_type='resource_target.created'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if targets != 0 || audits != 0 || events != 0 {
		t.Fatalf("failed create committed partial state: targets=%d audits=%d outbox=%d", targets, audits, events)
	}

	provider.resolveErr = nil
	target, err := svc.Create(ctx, "org:store", "user:admin", input)
	if err != nil {
		t.Fatal(err)
	}
	provider.resolveErr = resolveErr
	name := "must not persist"
	if _, err := svc.Update(ctx, target.OrgID, target.ID, "user:admin", PatchInput{Name: &name, Revision: target.Revision}); !errors.Is(err, resolveErr) {
		t.Fatalf("update decoration error = %v, want injected provider error", err)
	}
	stored, err := svc.store.Get(ctx, database.Pool, target.OrgID, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Name != input.Name || stored.Revision != 1 {
		t.Fatalf("failed update committed state: name=%q revision=%d", stored.Name, stored.Revision)
	}
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='resource_target.updated'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE event_type='resource_target.updated'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if audits != 0 || events != 0 {
		t.Fatalf("failed update committed audit/outbox: audits=%d outbox=%d", audits, events)
	}
}

func targetIDsForQA(targets []Target) []string {
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		out = append(out, target.ID)
	}
	return out
}
