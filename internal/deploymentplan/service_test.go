package deploymentplan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/oci"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
	"github.com/7K-Inari/inari-server/internal/types"
)

type fakeCatalog struct {
	mu                  sync.Mutex
	item                *types.CatalogItem
	version             *types.CatalogItemVersion
	packItem            *types.CatalogItem
	packVersion         *types.CatalogItemVersion
	admittedPackVersion *types.CatalogItemVersion
	admitErr            error
	admitted            []string
}

func (f *fakeCatalog) GetItemByID(_ context.Context, id string) (*types.CatalogItem, error) {
	if f.item != nil && id == f.item.ID {
		return f.item, nil
	}
	if f.packItem != nil && id == f.packItem.ID {
		return f.packItem, nil
	}
	return nil, catalog.ErrItemNotFound
}
func (f *fakeCatalog) EffectiveVersion(_ context.Context, _, id, _ string) (string, error) {
	if f.item != nil && id == f.item.ID {
		return f.version.Version, nil
	}
	if f.packItem != nil && id == f.packItem.ID {
		return f.packVersion.Version, nil
	}
	return "", catalog.ErrVersionNotFound
}
func (f *fakeCatalog) GetVersion(_ context.Context, id, version string) (*types.CatalogItemVersion, error) {
	if f.item != nil && id == f.item.ID && version == f.version.Version {
		return f.version, nil
	}
	if f.packItem != nil && id == f.packItem.ID && version == f.packVersion.Version {
		return f.packVersion, nil
	}
	return nil, catalog.ErrVersionNotFound
}
func (f *fakeCatalog) ListVersions(_ context.Context, id string) ([]types.CatalogItemVersion, error) {
	if f.packItem != nil && id == f.packItem.ID {
		return []types.CatalogItemVersion{*f.packVersion}, nil
	}
	if f.item != nil && id == f.item.ID {
		return []types.CatalogItemVersion{*f.version}, nil
	}
	return nil, catalog.ErrItemNotFound
}
func (f *fakeCatalog) ListVisible(_ context.Context, _ string, _ types.CatalogListOptions) ([]catalog.ItemView, int, error) {
	if f.item == nil {
		return nil, 0, nil
	}
	return []catalog.ItemView{{CatalogItem: *f.item, Versions: []types.CatalogItemVersion{*f.version}}}, 1, nil
}
func (f *fakeCatalog) EnsureVisible(context.Context, string, string, string) error { return nil }
func (f *fakeCatalog) AdmitVersion(_ context.Context, id, version string, _ trustedsource.Environment) (*catalog.AdmittedVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.admitErr != nil {
		return nil, f.admitErr
	}
	f.admitted = append(f.admitted, id+"@"+version)
	versionRow, err := f.GetVersion(context.Background(), id, version)
	if err != nil {
		return nil, err
	}
	if f.packItem != nil && id == f.packItem.ID && f.admittedPackVersion != nil {
		versionRow = f.admittedPackVersion
	}
	return &catalog.AdmittedVersion{Version: versionRow}, nil
}

type fakeTargets struct {
	appTarget    *resourcetargets.Target
	monTarget    *resourcetargets.Target
	provisionErr error
	resolveCalls []string
}

func (f *fakeTargets) List(_ context.Context, _, _ string, filter resourcetargets.ListFilter) ([]resourcetargets.Target, error) {
	if filter.Capability == resourcetargets.CapabilityDeploymentCluster && filter.Action == resourcetargets.ActionUse {
		return []resourcetargets.Target{*f.appTarget}, nil
	}
	if filter.Capability == resourcetargets.CapabilityMonitoringGrafana && filter.Action == resourcetargets.ActionProvision {
		return []resourcetargets.Target{*f.monTarget}, nil
	}
	return []resourcetargets.Target{}, nil
}
func (f *fakeTargets) Get(_ context.Context, _, _, id string) (*resourcetargets.Target, error) {
	if f.monTarget != nil && id == f.monTarget.ID {
		copy := *f.monTarget
		copy.EffectiveActions = []resourcetargets.Action{resourcetargets.ActionView}
		return &copy, nil
	}
	return nil, resourcetargets.ErrTargetNotFound
}
func (f *fakeTargets) Resolve(_ context.Context, in resourcetargets.ResolveInput) (*resourcetargets.ResolvedTarget, error) {
	f.resolveCalls = append(f.resolveCalls, in.TargetID+":"+string(in.Action))
	if in.TargetID == f.appTarget.ID {
		return &resourcetargets.ResolvedTarget{Target: *f.appTarget, Cluster: &types.Cluster{ID: "cluster-app", OrgID: "org-1", State: types.ClusterStateActive, Labels: map[string]string{"inari.dev/environment": "production"}}}, nil
	}
	if in.TargetID == f.monTarget.ID {
		if f.provisionErr != nil {
			return nil, f.provisionErr
		}
		return &resourcetargets.ResolvedTarget{Target: *f.monTarget, Selection: in.Selection, Cluster: &types.Cluster{ID: "cluster-mon", OrgID: "org-1", State: types.ClusterStateActive, Labels: map[string]string{"inari.dev/environment": "production"}}}, nil
	}
	return nil, resourcetargets.ErrTargetNotFound
}
func (f *fakeTargets) Providers() []resourcetargets.ProviderDescriptor { return nil }

type fakeExecutor struct {
	calls      int
	instanceID string
}

func (f *fakeExecutor) Execute(_ context.Context, _, _ string, plan *Plan) (*Execution, error) {
	f.calls++
	if plan.Source.Kind == SourceTemplate {
		return &Execution{ScaffoldRunID: "run-1"}, nil
	}
	if f.instanceID != "" {
		return &Execution{InstanceID: f.instanceID}, nil
	}
	return &Execution{InstanceID: "app-1"}, nil
}

type qaConcurrentExecutor struct {
	calls atomic.Int64
}

func (e *qaConcurrentExecutor) Execute(context.Context, string, string, *Plan) (*Execution, error) {
	e.calls.Add(1)
	return &Execution{InstanceID: "app-1"}, nil
}

type qaIdempotencyBarrierStore struct {
	*MemoryStore
	mu      sync.Mutex
	lookups int
	ready   chan struct{}
}

func newQAIdempotencyBarrierStore() *qaIdempotencyBarrierStore {
	return &qaIdempotencyBarrierStore{MemoryStore: NewMemoryStore(), ready: make(chan struct{})}
}

func (s *qaIdempotencyBarrierStore) GetPlanByIdempotency(ctx context.Context, orgID, requester, key string) (*Plan, error) {
	s.mu.Lock()
	if s.lookups < 2 {
		s.lookups++
		if s.lookups == 2 {
			close(s.ready)
		}
		ready := s.ready
		s.mu.Unlock()
		<-ready
		return nil, ErrPlanNotFound
	}
	s.mu.Unlock()
	return s.MemoryStore.GetPlanByIdempotency(ctx, orgID, requester, key)
}

type fakeInstances struct{ view *inventory.InstanceView }

func (f *fakeInstances) Get(_ context.Context, orgID, id string) (*inventory.InstanceView, error) {
	if f.view == nil || f.view.OrgID != orgID || f.view.ID != id {
		return nil, inventory.ErrInstanceNotFound
	}
	return f.view, nil
}

type fakeCharts struct {
	metadata []byte
	digest   string
	calls    int
}

func (f *fakeCharts) Fetch(_ context.Context, _ string) (*oci.Artifact, error) {
	f.calls++
	return &oci.Artifact{Digest: f.digest, Files: map[string][]byte{"Chart.yaml": []byte("version: 1.4.0\n"), "inari/observability.yaml": f.metadata}}, nil
}

func serviceFixture(t *testing.T) (*Service, *fakeCatalog, *fakeTargets, *fakeExecutor, *MemoryStore) {
	t.Helper()
	metadata := capabilityYAML(t)
	payload, _ := json.Marshal(map[string]any{"observabilityYaml": metadata, "observabilityRef": observability.PackReference{Package: "observability-pack", VersionRange: ">=0.2.0 <0.3.0"}, "admission": map[string]any{"type": "platform-app"}})
	packPayload, _ := json.Marshal(map[string]any{"rgd": `apiVersion: kro.run/v1alpha1
kind: ResourceGraphDefinition
metadata:
  annotations:
    inari.dev/observability-render-contract: inari.observability-pack/v2
spec:
  schema:
    spec: {org: string, namespace: string, app: string, team: string, folder: string, datasource: string, render: string, rulesLocal: boolean, rulesCentral: boolean}
  resources:
    - includeWhen: ['${schema.spec.rulesLocal}']
    - includeWhen: ['${schema.spec.rulesCentral}']
`, "admission": map[string]any{"type": "kro-rgd"}})
	cat := &fakeCatalog{
		item:        &types.CatalogItem{ID: "hiroba/payments-api", SourceID: "hiroba", Name: "payments-api"},
		version:     &types.CatalogItemVersion{ItemID: "hiroba/payments-api", Version: "1.4.0", ArtifactRef: "ghcr.io/7k-hiroba/payments-api/catalog/payments-api:1.4.0", ArtifactDigest: testDigest, ChartRef: "oci://ghcr.io/7k-hiroba/payments-api/charts/payments-api:1.4.0", ChartDigest: testDigest, Payload: payload},
		packItem:    &types.CatalogItem{ID: "hiroba/observability-pack", SourceID: "hiroba", Name: "observability-pack", Category: "observability"},
		packVersion: &types.CatalogItemVersion{ItemID: "hiroba/observability-pack", Version: "0.2.0", ArtifactRef: "ghcr.io/7k-hiroba/payments-api/catalog/observability-pack:0.2.0", ArtifactDigest: testDigest, Payload: packPayload},
	}
	appTarget := &resourcetargets.Target{ID: "rt-app", Revision: 4, ResourceRef: resourcetargets.TargetResourceRef{Kind: "cluster", ID: "cluster-app"}, Capabilities: []string{resourcetargets.CapabilityDeploymentCluster}, Enabled: true, Readiness: resourcetargets.Readiness{State: resourcetargets.ReadinessReady}}
	monTarget := &resourcetargets.Target{ID: "rt-mon", Revision: 7, IsDefault: true, ResourceRef: resourcetargets.TargetResourceRef{Kind: "cluster", ID: "cluster-mon"}, Capabilities: []string{resourcetargets.CapabilityMonitoringGrafana}, Enabled: true, Readiness: resourcetargets.Readiness{State: resourcetargets.ReadinessReady}, Config: json.RawMessage(`{"baseUrl":"https://grafana.team.example","evaluation":"central","folderPrefixes":["acme-inc"],"datasources":[{"name":"metrics-central","type":"prometheus"}]}`)}
	targets := &fakeTargets{appTarget: appTarget, monTarget: monTarget}
	executor := &fakeExecutor{}
	store := NewMemoryStore()
	svc := NewService(nil, store).WithDependencies(cat, targets, &fakeCharts{metadata: []byte(metadata), digest: testDigest}, executor).
		WithTeams(TeamListerFunc(func(context.Context, string) ([]types.Team, error) {
			return []types.Team{{ID: "team-1", Name: "payments-api-maintainers", OrgID: "org-1"}}, nil
		}))
	svc.now = func() time.Time { return time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC) }
	return svc, cat, targets, executor, store
}

func deployRequest() PlanRequest {
	return PlanRequest{
		Operation: OperationDeploy, Source: &Source{Kind: SourceCatalog, ItemID: "hiroba/payments-api", Version: "1.4.0"},
		Deployment:    DeploymentInput{TargetID: "rt-app", TargetRevision: 4, Name: "payments", Namespace: "payments", OwnerTeam: "payments-api-maintainers", Spec: json.RawMessage(`{"replicas":2}`)},
		Observability: ObservabilityInput{Mode: ModeProvision}, IdempotencyKey: "request-1",
	}
}

func TestPreflightNormalizesAssetsPinsAndPolicyDefault(t *testing.T) {
	svc, _, _, _, _ := serviceFixture(t)
	preflight, err := svc.Preflight(context.Background(), deployRequest(), "org-1", "acme-inc", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	plan := preflight.Plan
	if plan.Capability == nil || len(plan.Capability.Dashboards) != 1 || plan.App.Digest != testDigest || plan.App.Version != "1.4.0" {
		t.Fatalf("plan = %#v", plan)
	}
	if len(preflight.CompatiblePacks) != 1 || preflight.CompatiblePacks[0].Version != "0.2.0" || preflight.CompatiblePacks[0].RenderContract != observability.PackRenderContractV2 {
		t.Fatalf("packs = %#v", preflight.CompatiblePacks)
	}
	if len(preflight.MonitoringTargets) != 1 || plan.Observability.Target == nil || plan.Observability.Target.ID != "rt-mon" {
		t.Fatalf("targets/default = %#v / %#v", preflight.MonitoringTargets, plan.Observability.Target)
	}
	if plan.Observability.Pack == nil || plan.PlanFingerprint == "" || plan.Gate.CompanionRendering {
		t.Fatalf("plan pins/gate = %#v", plan)
	}
}

func reviewedRequest(t *testing.T, svc *Service, req PlanRequest) PlanRequest {
	t.Helper()
	review, err := svc.Preflight(context.Background(), req, "org-1", "acme-inc", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	req.Source = &review.Plan.Source
	req.Deployment = review.Plan.Deployment
	req.Observability = review.Plan.Observability
	req.PlanFingerprint = review.Plan.PlanFingerprint
	return req
}

func submitReviewed(t *testing.T, svc *Service, req PlanRequest) (*Plan, error) {
	t.Helper()
	return svc.Submit(context.Background(), reviewedRequest(t, svc, req), "org-1", "acme-inc", "user-1")
}

func TestSubmitRequiresReviewedExactSourcePins(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Source)
	}{
		{name: "version", mutate: func(source *Source) { source.Version = "" }},
		{name: "digest", mutate: func(source *Source) { source.Digest = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _, executor, _ := serviceFixture(t)
			req := deployRequest()
			tc.mutate(req.Source)
			initial, err := svc.Preflight(context.Background(), req, "org-1", "acme-inc", "user-1")
			if err != nil {
				t.Fatal(err)
			}
			req.PlanFingerprint = initial.Plan.PlanFingerprint
			if _, err := svc.Submit(context.Background(), req, "org-1", "acme-inc", "user-1"); err == nil {
				t.Fatal("submit accepted a mutable source pin")
			}
			if executor.calls != 0 {
				t.Fatal("application executed with a mutable source pin")
			}
		})
	}
}

func TestSubmitRequiresPlanFingerprint(t *testing.T) {
	svc, _, _, executor, _ := serviceFixture(t)
	req := deployRequest()
	req.Source.Digest = testDigest
	if _, err := svc.Submit(context.Background(), req, "org-1", "acme-inc", "user-1"); err == nil {
		t.Fatal("submit accepted a plan without a review fingerprint")
	}
	if executor.calls != 0 {
		t.Fatal("application executed without plan freshness validation")
	}
}

func TestPreflightReturnsExactNormalizedSourcePin(t *testing.T) {
	svc, _, _, _, _ := serviceFixture(t)
	initial, err := svc.Preflight(context.Background(), deployRequest(), "org-1", "acme-inc", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if initial.Plan.Source.Version != "1.4.0" || initial.Plan.Source.Digest != testDigest {
		t.Fatalf("normalized source pin = %#v", initial.Plan.Source)
	}
}

func TestSubmitSkipExecutesAppWithoutCompanion(t *testing.T) {
	svc, _, _, executor, _ := serviceFixture(t)
	req := deployRequest()
	req.Observability.Mode = ModeSkip
	plan, err := submitReviewed(t, svc, req)
	if err != nil {
		t.Fatal(err)
	}
	if executor.calls != 1 || plan.AppInstanceID != "app-1" || plan.Companion != nil {
		t.Fatalf("submit = %#v, calls %d", plan, executor.calls)
	}
	var spec map[string]any
	if err := json.Unmarshal(plan.RenderIntent.AppSpec, &spec); err != nil {
		t.Fatal(err)
	}
	if spec["observability"].(map[string]any)["enabled"] != false {
		t.Fatalf("chart-native overlay missing: %#v", spec)
	}
}

func TestQASubmitConcurrentSameIdempotencyKeyReturnsOnePlan(t *testing.T) {
	svc, cat, _, _, _ := serviceFixture(t)
	cat.version.ChartRef, cat.version.ChartDigest = "", ""
	store := newQAIdempotencyBarrierStore()
	executor := &qaConcurrentExecutor{}
	svc.store, svc.executor = store, executor
	request := deployRequest()
	request.Observability.Mode = ModeSkip
	request.Deployment.TargetID = ""
	review, err := svc.Preflight(context.Background(), request, "org-1", "acme-inc", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	request.Source = &review.Plan.Source
	request.Deployment = review.Plan.Deployment
	request.Observability = review.Plan.Observability
	request.PlanFingerprint = review.Plan.PlanFingerprint

	type outcome struct {
		plan *Plan
		err  error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			plan, err := svc.Submit(context.Background(), request, "org-1", "acme-inc", "user-1")
			results <- outcome{plan: plan, err: err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent submits: first=%v second=%v", first.err, second.err)
	}
	if first.plan.ID != second.plan.ID || executor.calls.Load() != 1 {
		t.Fatalf("same key produced plans %s/%s and %d executions", first.plan.ID, second.plan.ID, executor.calls.Load())
	}
}

func TestSubmitProvisionClosedGateRevalidatesAndHasNoLinks(t *testing.T) {
	svc, cat, targets, executor, _ := serviceFixture(t)
	req := reviewedRequest(t, svc, deployRequest())
	cat.admitted = nil
	targets.resolveCalls = nil
	plan, err := svc.Submit(context.Background(), req, "org-1", "acme-inc", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if executor.calls != 1 || plan.Companion == nil || plan.Companion.State != "blocked_external_gate" || len(plan.Companion.Links) != 0 {
		t.Fatalf("plan = %#v", plan)
	}
	if len(cat.admitted) != 2 || len(targets.resolveCalls) != 2 {
		t.Fatalf("admission/target revalidation = %v / %v", cat.admitted, targets.resolveCalls)
	}
	if plan.RenderIntent == nil || plan.RenderIntent.PackSpec["rulesCentral"] != true || plan.RenderIntent.PackSpec["rulesLocal"] != false {
		t.Fatalf("render intent = %#v", plan.RenderIntent)
	}
}

func TestSubmitRequiresExactCompatiblePackPin(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PackPin)
	}{
		{name: "render contract", mutate: func(pin *PackPin) { pin.RenderContract = "inari.observability-pack/v1" }},
		{name: "source", mutate: func(pin *PackPin) { pin.SourceID = "other" }},
		{name: "package version", mutate: func(pin *PackPin) { pin.PackageVersion = "9.9.9" }},
		{name: "artifact ref", mutate: func(pin *PackPin) { pin.Ref = "ghcr.io/other/pack:0.2.0" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _, executor, _ := serviceFixture(t)
			req := deployRequest()
			initial, err := svc.Preflight(context.Background(), req, "org-1", "acme-inc", "user-1")
			if err != nil {
				t.Fatal(err)
			}
			pin := initial.CompatiblePacks[0]
			tc.mutate(&pin)
			req.Observability.Pack = &pin
			req = reviewedRequest(t, svc, req)
			if _, err := svc.Submit(context.Background(), req, "org-1", "acme-inc", "user-1"); err == nil {
				t.Fatal("submit accepted a pack pin that was not an exact compatible candidate")
			}
			if executor.calls != 0 {
				t.Fatal("application executed after invalid pack selection")
			}
		})
	}
}

func TestSubmitRevalidatesAdmittedPackPayload(t *testing.T) {
	svc, cat, _, executor, _ := serviceFixture(t)
	req := deployRequest()
	initial, err := svc.Preflight(context.Background(), req, "org-1", "acme-inc", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	pin := initial.CompatiblePacks[0]
	req.Source = &initial.Plan.Source
	req.Deployment = initial.Plan.Deployment
	req.Observability = initial.Plan.Observability
	req.Observability.Pack = &pin
	req.PlanFingerprint = initial.Plan.PlanFingerprint
	invalid := *cat.packVersion
	invalid.Payload = json.RawMessage(`{"admission":{"type":"kro-rgd"},"rgd":"kind: ResourceGraphDefinition"}`)
	cat.admittedPackVersion = &invalid
	if _, err := svc.Submit(context.Background(), req, "org-1", "acme-inc", "user-1"); err == nil {
		t.Fatal("submit accepted an admitted pack without the required v2 RGD contract")
	}
	if executor.calls != 0 {
		t.Fatal("application executed after invalid admitted pack payload")
	}
}

func TestSubmitRevokedProvisionGrantStopsBeforeExecution(t *testing.T) {
	svc, _, targets, executor, _ := serviceFixture(t)
	targets.provisionErr = resourcetargets.ErrTargetDenied
	if _, err := submitReviewed(t, svc, deployRequest()); !errors.Is(err, resourcetargets.ErrTargetDenied) {
		t.Fatalf("error = %v", err)
	}
	if executor.calls != 0 {
		t.Fatal("app executed after companion authorization failure")
	}
}

func TestDirectChartAndDeploymentCapableTemplateNormalize(t *testing.T) {
	for _, source := range []Source{
		{Kind: SourceChart, SourceID: "hiroba", Ref: "oci://ghcr.io/7k-hiroba/payments-api/charts/payments-api", Version: "1.4.0", Digest: testDigest},
		{Kind: SourceTemplate, ItemID: "hiroba/payments-api", Version: "1.4.0"},
	} {
		t.Run(string(source.Kind), func(t *testing.T) {
			svc, cat, _, _, _ := serviceFixture(t)
			if source.Kind == SourceTemplate {
				payload, _ := json.Marshal(map[string]any{"manifest": map[string]any{"kind": "component", "observability": map[string]any{"manifest": "observability/observability.yaml"}}, "observabilityYaml": capabilityYAML(t)})
				cat.version.Payload = payload
				cat.version.ChartRef = ""
				cat.version.ChartDigest = ""
			}
			req := deployRequest()
			req.Source = &source
			preflight, err := svc.Preflight(context.Background(), req, "org-1", "acme-inc", "user-1")
			if err != nil {
				t.Fatal(err)
			}
			if preflight.Plan.Capability == nil || preflight.Plan.App.Version != "1.4.0" || preflight.Plan.App.Digest != testDigest {
				t.Fatalf("normalized %s plan = %#v", source.Kind, preflight.Plan)
			}
		})
	}
}

func TestPureTemplateHasNoObservabilityCapability(t *testing.T) {
	svc, cat, _, _, _ := serviceFixture(t)
	payload, _ := json.Marshal(map[string]any{"manifest": map[string]any{"kind": "gitops-repo"}})
	cat.version.ChartRef = ""
	cat.version.ChartDigest = ""
	cat.version.Payload = payload
	req := deployRequest()
	req.Source = &Source{Kind: SourceTemplate, ItemID: cat.item.ID, Version: "1.4.0"}
	preflight, err := svc.Preflight(context.Background(), req, "org-1", "acme-inc", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if preflight.Plan.Capability != nil || preflight.Plan.Observability.Mode != ModeNone || len(preflight.MonitoringTargets) != 0 || len(preflight.CompatiblePacks) != 0 {
		t.Fatalf("pure template preflight = %#v", preflight)
	}
}

func TestExistingInstanceCanProvisionFromOriginalPins(t *testing.T) {
	svc, _, _, _, _ := serviceFixture(t)
	req := deployRequest()
	req.Observability.Mode = ModeSkip
	original, err := submitReviewed(t, svc, req)
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := svc.Preflight(context.Background(), PlanRequest{Operation: OperationProvisionExisting, InstanceID: original.AppInstanceID, Observability: ObservabilityInput{Mode: ModeProvision}}, "org-1", "acme-inc", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if preflight.Plan.App.Digest != original.App.Digest || preflight.Plan.App.Version != original.App.Version || preflight.Plan.Capability == nil {
		t.Fatalf("existing plan = %#v", preflight.Plan)
	}
	submitted, err := svc.Submit(context.Background(), PlanRequest{Operation: OperationProvisionExisting, InstanceID: original.AppInstanceID, Observability: preflight.Plan.Observability, PlanFingerprint: preflight.Plan.PlanFingerprint, IdempotencyKey: "request-2"}, "org-1", "acme-inc", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if submitted.Companion == nil || submitted.Companion.AppInstanceID != original.AppInstanceID {
		t.Fatalf("existing companion = %#v", submitted.Companion)
	}
}

func TestVerificationGatesReadyLinksAndRejectsBlockedIntent(t *testing.T) {
	svc, _, _, _, store := serviceFixture(t)
	plan, err := submitReviewed(t, svc, deployRequest())
	if err != nil {
		t.Fatal(err)
	}
	result := verifiedResult(t, plan.Capability)
	result.Companion.ID = plan.Companion.ID
	result.Companion.Generation = plan.Companion.Generation
	result.Target.ID = plan.Companion.TargetID
	result.Target.Revision = plan.Companion.TargetRevision
	result.Target.ClusterID = plan.Companion.TargetClusterID
	result.App.PlanID = plan.ID
	result.App.InstanceID = plan.AppInstanceID
	result.App.SourceDigest = plan.App.Digest
	result.App.Revision = plan.Companion.AppRevision
	result.Pack.ItemID = plan.Companion.Pack.ItemID
	result.Pack.Version = plan.Companion.Pack.Version
	result.Pack.Digest = plan.Companion.Pack.Digest
	if _, err := svc.ApplyVerification(context.Background(), "org-1", result); err == nil {
		t.Fatal("blocked intent accepted deployed verification")
	}
	plan.Companion.CompanionInstanceID = "companion-1"
	plan.Companion.State = "verification_pending"
	if err := store.UpdatePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	companion, err := svc.ApplyVerification(context.Background(), "org-1", result)
	if err != nil {
		t.Fatal(err)
	}
	if companion.State != "ready" {
		t.Fatalf("companion state = %s", companion.State)
	}
	status, err := svc.InstanceObservability(context.Background(), "org-1", plan.AppInstanceID, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Companion.Links) != 1 || !strings.Contains(status.Companion.Links[0].URL, "var-namespace=payments") {
		t.Fatalf("ready links = %#v", status.Companion.Links)
	}
}

func TestVerificationRejectsEvidenceOutsideApprovedSelection(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*observability.VerificationResult)
	}{
		{name: "folder", mutate: func(result *observability.VerificationResult) { result.Checks.Folder.Name = "acme-inc/other" }},
		{name: "datasource name", mutate: func(result *observability.VerificationResult) { result.Checks.Datasources[0].Name = "other" }},
		{name: "datasource logical", mutate: func(result *observability.VerificationResult) { result.Checks.Datasources[0].Logical = "other" }},
		{name: "datasource type", mutate: func(result *observability.VerificationResult) { result.Checks.Datasources[0].Type = "loki" }},
		{name: "owner team", mutate: func(result *observability.VerificationResult) { result.Checks.Access.Team = "other-team" }},
		{name: "selected rule", mutate: func(result *observability.VerificationResult) { result.Checks.Rules[0].File = "rules/other.yaml" }},
		{name: "extra rule", mutate: func(result *observability.VerificationResult) {
			result.Checks.Rules = append(result.Checks.Rules, observability.RuleCheck{Check: observability.Check{State: "passed"}, File: "rules/service.yaml", Evaluation: observability.EvaluationLocal})
		}},
		{name: "extra dashboard", mutate: func(result *observability.VerificationResult) {
			result.Checks.Dashboards = append(result.Checks.Dashboards, observability.DashboardCheck{Check: observability.Check{State: "passed"}, UID: "payments-api-extra", Title: "Extra", Slug: "extra"})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _, _, store := serviceFixture(t)
			plan, err := submitReviewed(t, svc, deployRequest())
			if err != nil {
				t.Fatal(err)
			}
			plan.Companion.CompanionInstanceID = "companion-1"
			plan.Companion.State = "verification_pending"
			if err := store.UpdatePlan(context.Background(), plan); err != nil {
				t.Fatal(err)
			}
			result := verifiedResult(t, plan.Capability)
			result.Companion.ID = plan.Companion.ID
			result.Companion.Generation = plan.Companion.Generation
			result.Target.ID = plan.Companion.TargetID
			result.Target.Revision = plan.Companion.TargetRevision
			result.Target.ClusterID = plan.Companion.TargetClusterID
			result.App.PlanID = plan.ID
			result.App.InstanceID = plan.AppInstanceID
			result.App.SourceDigest = plan.App.Digest
			result.App.Revision = plan.Companion.AppRevision
			result.Pack.ItemID = plan.Companion.Pack.ItemID
			result.Pack.Version = plan.Companion.Pack.Version
			result.Pack.Digest = plan.Companion.Pack.Digest
			tc.mutate(result)
			if _, err := svc.ApplyVerification(context.Background(), "org-1", result); err == nil {
				t.Fatal("mismatched evidence changed readiness")
			}
		})
	}
}

func TestInstanceLinksRejectPersistedEvidenceThatDoesNotMatchSelection(t *testing.T) {
	svc, _, _, _, store := serviceFixture(t)
	plan, err := submitReviewed(t, svc, deployRequest())
	if err != nil {
		t.Fatal(err)
	}
	plan.Companion.CompanionInstanceID = "companion-1"
	plan.Companion.State = "ready"
	result := verifiedResult(t, plan.Capability)
	result.Companion.ID = plan.Companion.ID
	result.Companion.Generation = plan.Companion.Generation
	result.Target.ID = plan.Companion.TargetID
	result.Target.Revision = plan.Companion.TargetRevision
	result.Target.ClusterID = plan.Companion.TargetClusterID
	result.App.PlanID = plan.ID
	result.App.InstanceID = plan.AppInstanceID
	result.App.SourceDigest = plan.App.Digest
	result.App.Revision = plan.Companion.AppRevision
	result.Pack.ItemID = plan.Companion.Pack.ItemID
	result.Pack.Version = plan.Companion.Pack.Version
	result.Pack.Digest = plan.Companion.Pack.Digest
	result.Checks.Datasources[0].Name = "other"
	plan.Companion.Verification = result
	if err := store.UpdatePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	status, err := svc.InstanceObservability(context.Background(), "org-1", plan.AppInstanceID, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Companion.Links) != 0 {
		t.Fatal("links survived mismatched persisted datasource evidence")
	}
}

func TestInstanceStatusNeverUsesCompanionFromOlderPlan(t *testing.T) {
	svc, _, _, _, store := serviceFixture(t)
	original, err := submitReviewed(t, svc, deployRequest())
	if err != nil {
		t.Fatal(err)
	}
	original.Companion.CompanionInstanceID = "companion-1"
	original.Companion.State = "verification_pending"
	if err := store.UpdatePlan(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyVerification(context.Background(), "org-1", resultForPlan(t, original)); err != nil {
		t.Fatal(err)
	}
	now := svc.now()
	svc.now = func() time.Time { return now.Add(time.Second) }
	request := PlanRequest{Operation: OperationProvisionExisting, InstanceID: original.AppInstanceID, Observability: ObservabilityInput{Mode: ModeSkip}, IdempotencyKey: "request-skip"}
	review, err := svc.Preflight(context.Background(), request, "org-1", "acme-inc", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	request.PlanFingerprint = review.Plan.PlanFingerprint
	if _, err := svc.Submit(context.Background(), request, "org-1", "acme-inc", "user-1"); err != nil {
		t.Fatal(err)
	}
	status, err := svc.InstanceObservability(context.Background(), "org-1", original.AppInstanceID, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if status.Mode != ModeSkip || status.Companion != nil {
		t.Fatalf("newer skip plan inherited an older companion: %#v", status)
	}
}

func TestGetPlanDoesNotReplaceCompanionFromNewerPlan(t *testing.T) {
	svc, _, _, _, _ := serviceFixture(t)
	original, err := submitReviewed(t, svc, deployRequest())
	if err != nil {
		t.Fatal(err)
	}
	now := svc.now()
	svc.now = func() time.Time { return now.Add(time.Second) }
	request := PlanRequest{Operation: OperationProvisionExisting, InstanceID: original.AppInstanceID, Observability: ObservabilityInput{Mode: ModeProvision}, IdempotencyKey: "request-newer"}
	newer, err := submitReviewed(t, svc, request)
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Get(context.Background(), "org-1", original.ID, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Companion == nil || got.Companion.PlanID != original.ID || got.Companion.ID == newer.Companion.ID {
		t.Fatalf("historical plan inherited a newer companion: got %#v, newer %#v", got.Companion, newer.Companion)
	}
}

func TestLegacyCatalogInstanceCanProvisionFromRecordedPin(t *testing.T) {
	svc, _, _, _, _ := serviceFixture(t)
	svc.WithInstances(&fakeInstances{view: &inventory.InstanceView{ResourceInstance: types.ResourceInstance{
		ID: "legacy-1", OrgID: "org-1", ClusterID: "cluster-app", CatalogItemID: "hiroba/payments-api", Version: "1.4.0", ArtifactDigest: testDigest,
		OwnerTeam: "payments-api-maintainers", Spec: json.RawMessage(`{"replicas":2}`), ResourceRef: types.ResourceRef{Name: "payments", Namespace: "payments"}, RepoID: "repo-1",
	}}})
	status, err := svc.InstanceObservability(context.Background(), "org-1", "legacy-1", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if status.Mode != ModeSkip || !status.Available || status.Companion != nil {
		t.Fatalf("legacy status = %#v", status)
	}
	preflight, err := svc.Preflight(context.Background(), PlanRequest{Operation: OperationProvisionExisting, InstanceID: "legacy-1", Observability: ObservabilityInput{Mode: ModeProvision}}, "org-1", "acme-inc", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if preflight.Plan.AppInstanceID != "legacy-1" || preflight.Plan.App.Digest != testDigest || preflight.Plan.Capability == nil || preflight.Plan.Deployment.TargetID != "rt-app" {
		t.Fatalf("legacy preflight = %#v", preflight.Plan)
	}
}

func TestLegacyInstanceStatusFailsClosedWithoutOriginalDigest(t *testing.T) {
	svc, _, _, _, _ := serviceFixture(t)
	svc.WithInstances(&fakeInstances{view: &inventory.InstanceView{ResourceInstance: types.ResourceInstance{
		ID: "legacy-1", OrgID: "org-1", ClusterID: "cluster-app", CatalogItemID: "hiroba/payments-api", Version: "1.4.0",
		OwnerTeam: "payments-api-maintainers", ResourceRef: types.ResourceRef{Name: "payments", Namespace: "payments"},
	}}})
	status, err := svc.InstanceObservability(context.Background(), "org-1", "legacy-1", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if status.Available || status.Companion != nil || status.Mode != ModeNone || !strings.Contains(status.Reason, "capability_unavailable") {
		t.Fatalf("legacy status without provenance = %#v", status)
	}
}

func TestProvisionRejectsUnknownOwnerTeam(t *testing.T) {
	svc, _, _, _, _ := serviceFixture(t)
	req := deployRequest()
	req.Deployment.OwnerTeam = "other-team"
	if _, err := svc.Preflight(context.Background(), req, "org-1", "acme-inc", "user-1"); err == nil || !strings.Contains(err.Error(), "current org") {
		t.Fatalf("error = %v", err)
	}
}

func resultForPlan(t *testing.T, plan *Plan) *observability.VerificationResult {
	t.Helper()
	result := verifiedResult(t, plan.Capability)
	result.Companion.ID = plan.Companion.ID
	result.Companion.Generation = plan.Companion.Generation
	result.Target.ID = plan.Companion.TargetID
	result.Target.Revision = plan.Companion.TargetRevision
	result.Target.ClusterID = plan.Companion.TargetClusterID
	result.App.PlanID = plan.ID
	result.App.InstanceID = plan.AppInstanceID
	result.App.SourceDigest = plan.App.Digest
	result.App.Revision = plan.Companion.AppRevision
	result.Pack.ItemID = plan.Companion.Pack.ItemID
	result.Pack.Version = plan.Companion.Pack.Version
	result.Pack.Digest = plan.Companion.Pack.Digest
	return result
}

func TestVerificationDuplicateAndOlderResultsCannotChangeReadiness(t *testing.T) {
	svc, _, _, _, store := serviceFixture(t)
	plan, err := submitReviewed(t, svc, deployRequest())
	if err != nil {
		t.Fatal(err)
	}
	plan.Companion.CompanionInstanceID = "companion-1"
	plan.Companion.State = "verification_pending"
	if err := store.UpdatePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	result := resultForPlan(t, plan)
	ready, err := svc.ApplyVerification(context.Background(), "org-1", result)
	if err != nil {
		t.Fatal(err)
	}
	if ready.State != "ready" {
		t.Fatalf("initial state = %s", ready.State)
	}
	duplicate := resultForPlan(t, plan)
	duplicate.Result = "failed"
	duplicate.Run.FinishedAt = duplicate.Run.FinishedAt.Add(time.Minute)
	got, err := svc.ApplyVerification(context.Background(), "org-1", duplicate)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "ready" || !got.UpdatedAt.Equal(ready.UpdatedAt) || got.Verification.Result != "passed" {
		t.Fatalf("duplicate run changed readiness: %#v", got)
	}
	older := resultForPlan(t, plan)
	older.Run.ID = "vr-older"
	older.Run.FinishedAt = result.Run.FinishedAt.Add(-time.Minute)
	older.Result = "failed"
	if _, err := svc.ApplyVerification(context.Background(), "org-1", older); err == nil {
		t.Fatal("older evidence replaced current readiness")
	}
}

func TestVerificationStoreRejectsStaleCompanionSnapshot(t *testing.T) {
	svc, _, _, _, store := serviceFixture(t)
	plan, err := submitReviewed(t, svc, deployRequest())
	if err != nil {
		t.Fatal(err)
	}
	plan.Companion.CompanionInstanceID = "companion-1"
	plan.Companion.State = "verification_pending"
	if err := store.UpdatePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	current, err := store.GetCompanion(context.Background(), "org-1", plan.Companion.ID)
	if err != nil {
		t.Fatal(err)
	}
	firstResult := resultForPlan(t, plan)
	first := current.DeepCopy()
	first.State = "ready"
	first.Verification = firstResult
	applied, err := store.SaveVerification(context.Background(), "org-1", first, firstResult, "")
	if err != nil || !applied {
		t.Fatalf("first verification applied=%t, err=%v", applied, err)
	}
	staleResult := resultForPlan(t, plan)
	staleResult.Run.ID = "vr-stale"
	staleResult.Run.FinishedAt = staleResult.Run.FinishedAt.Add(time.Minute)
	stale := current.DeepCopy()
	stale.State = "verification_failed"
	stale.Verification = staleResult
	if applied, err := store.SaveVerification(context.Background(), "org-1", stale, staleResult, ""); !errors.Is(err, ErrPlanConflict) || applied {
		t.Fatalf("stale verification applied=%t, err=%v", applied, err)
	}
	got, err := store.GetCompanion(context.Background(), "org-1", plan.Companion.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "ready" || got.Verification.Run.ID != firstResult.Run.ID {
		t.Fatalf("stale snapshot overwrote current companion: %#v", got)
	}
}

func TestVerificationRejectsWrongGeneration(t *testing.T) {
	svc, _, _, _, _ := serviceFixture(t)
	plan, err := submitReviewed(t, svc, deployRequest())
	if err != nil {
		t.Fatal(err)
	}
	result := verifiedResult(t, plan.Capability)
	result.Companion.ID = plan.Companion.ID
	result.Companion.Generation = plan.Companion.Generation + 1
	if _, err := svc.ApplyVerification(context.Background(), "org-1", result); err == nil {
		t.Fatal("wrong-generation verification accepted")
	}
}
