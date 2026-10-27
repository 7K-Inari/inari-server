package addons

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// --- fakes -----------------------------------------------------------------

type fakeStore struct {
	mu        sync.Mutex                     // guards the claim path (concurrent adopts)
	addons    map[string]*types.ClusterAddon // key: clusterID + "|" + catalogItem
	repos     map[string]*types.TenantGitRepo
	baselines map[string]string // clusterID → repo selector
}

func newFakeStore() *fakeStore {
	return &fakeStore{addons: map[string]*types.ClusterAddon{}, repos: map[string]*types.TenantGitRepo{}, baselines: map[string]string{}}
}

func addonKey(clusterID, item string) string { return clusterID + "|" + item }

func (f *fakeStore) GetClusterAddon(_ context.Context, _ db.Querier, orgID, clusterID, item string) (*types.ClusterAddon, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.addons[addonKey(clusterID, item)]
	if !ok || a.OrgID != orgID {
		return nil, inventory.ErrAddonNotFound
	}
	return a, nil
}

func (f *fakeStore) GetClusterAddonByID(_ context.Context, _ db.Querier, orgID, id string) (*types.ClusterAddon, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.addons {
		if a.ID == id && a.OrgID == orgID {
			return a, nil
		}
	}
	return nil, inventory.ErrAddonNotFound
}

func (f *fakeStore) ListClusterAddons(_ context.Context, _ db.Querier, orgID, clusterID string) ([]*types.ClusterAddon, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*types.ClusterAddon
	for _, a := range f.addons {
		// Mirror the SQL: a cluster listing includes fleet ('*') rows.
		if a.OrgID == orgID && (clusterID == "" || a.ClusterID == clusterID || a.ClusterID == "*") {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeStore) UpsertClusterAddon(_ context.Context, _ db.Querier, a *types.ClusterAddon) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *a
	f.addons[addonKey(a.ClusterID, a.CatalogItem)] = &cp
	return nil
}

func (f *fakeStore) UpsertDiscoveredAddon(_ context.Context, _ db.Querier, a *types.ClusterAddon) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := addonKey(a.ClusterID, a.CatalogItem)
	if existing, ok := f.addons[key]; ok {
		// Mirror the SQL guard: never touch non-discovered rows.
		if existing.State != types.AddonStateDiscovered {
			return nil
		}
		existing.DiscoveredMeta = a.DiscoveredMeta
		if a.ChartVersion != "" {
			existing.ChartVersion = a.ChartVersion
		}
		return nil
	}
	cp := *a
	if cp.ID == "" {
		cp.ID = "addon-" + a.CatalogItem
	}
	f.addons[key] = &cp
	return nil
}

// AbsorbDiscoveredAddons mirrors the SQL: delete the item's per-cluster
// discovered rows (never the '*' fleet row), returning their sightings.
func (f *fakeStore) AbsorbDiscoveredAddons(_ context.Context, _ db.Querier, orgID, item string) ([]json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []json.RawMessage
	for k, a := range f.addons {
		if a.OrgID == orgID && a.CatalogItem == item && a.State == types.AddonStateDiscovered && a.ClusterID != "*" {
			if len(a.DiscoveredMeta) > 0 {
				out = append(out, a.DiscoveredMeta)
			}
			delete(f.addons, k)
		}
	}
	return out, nil
}

// ClaimClusterAddonForAdoption mirrors the SQL claim atomically (mutex).
// The stale-claim reclaim window is not simulated.
func (f *fakeStore) ClaimClusterAddonForAdoption(_ context.Context, _ db.Querier, a *types.ClusterAddon) (string, json.RawMessage, bool, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := addonKey(a.ClusterID, a.CatalogItem)
	if ex, ok := f.addons[key]; ok {
		if ex.State != types.AddonStateDiscovered {
			return "", nil, false, false, nil
		}
		ex.State = types.AddonStateAdopting
		return ex.ID, ex.DiscoveredMeta, false, true, nil
	}
	cp := *a
	cp.State = types.AddonStateAdopting
	if cp.ID == "" {
		cp.ID = "addon-" + a.CatalogItem
	}
	f.addons[key] = &cp
	return cp.ID, nil, true, true, nil
}

func (f *fakeStore) ReleaseClusterAddonClaim(_ context.Context, _ db.Querier, orgID, id string, inserted bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, a := range f.addons {
		if a.ID == id && a.OrgID == orgID && a.State == types.AddonStateAdopting {
			if inserted {
				delete(f.addons, k)
			} else {
				a.State = types.AddonStateDiscovered
			}
		}
	}
	return nil
}

func (f *fakeStore) DeleteClusterAddon(_ context.Context, _ db.Querier, orgID, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, a := range f.addons {
		if a.ID == id && a.OrgID == orgID {
			delete(f.addons, k)
			return nil
		}
	}
	return inventory.ErrAddonNotFound
}

func (f *fakeStore) BaselineRepoSelector(_ context.Context, _ db.Querier, _, clusterID string) (string, error) {
	return f.baselines[clusterID], nil
}

func (f *fakeStore) SetClusterAddonState(_ context.Context, _ db.Querier, orgID, id string, state types.AddonState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.addons {
		if a.ID == id && a.OrgID == orgID {
			a.State = state
			return nil
		}
	}
	return inventory.ErrAddonNotFound
}

func (f *fakeStore) GetGitRepo(_ context.Context, _ db.Querier, orgID, id string) (*types.TenantGitRepo, error) {
	r, ok := f.repos[id]
	if !ok || r.OrgID != orgID {
		return nil, inventory.ErrRepoNotFound
	}
	return r, nil
}

// repoStoreAdapter adapts fakeStore to gitprovider.RepoStore (querier-less).
type fakeRepoStoreAdapter struct{ f *fakeStore }

func (a fakeRepoStoreAdapter) GetGitRepo(_ context.Context, orgID, id string) (*types.TenantGitRepo, error) {
	return a.f.GetGitRepo(context.Background(), nil, orgID, id)
}

func (a fakeRepoStoreAdapter) GetDefaultGitRepo(_ context.Context, orgID string) (*types.TenantGitRepo, error) {
	for _, r := range a.f.repos {
		if r.OrgID == orgID && r.IsDefault {
			return r, nil
		}
	}
	return nil, inventory.ErrRepoNotFound
}

type fakeCatalog struct {
	items    map[string]*types.CatalogItem
	versions map[string][]types.CatalogItemVersion
}

var certManagerSchema = json.RawMessage(`{"type":"object","properties":{"crds":{"type":"object","properties":{"enabled":{"type":"boolean"}}},"replicaCount":{"type":"integer","minimum":1}}}`)

func newFakeCatalog() *fakeCatalog {
	return &fakeCatalog{
		items: map[string]*types.CatalogItem{
			"platform:cert-manager": {ID: "platform:cert-manager", Name: "cert-manager", Source: types.CatalogSourcePlatform},
		},
		versions: map[string][]types.CatalogItemVersion{
			"platform:cert-manager": {
				{ItemID: "platform:cert-manager", Version: "v1.16.1", Channel: "stable",
					Schema:  certManagerSchema,
					Payload: json.RawMessage(`{"chart":{"repoURL":"https://charts.jetstack.io","chart":"cert-manager","namespace":"cert-manager"}}`)},
				{ItemID: "platform:cert-manager", Version: "v1.16.2", Channel: "stable",
					Schema:  certManagerSchema,
					Payload: json.RawMessage(`{"chart":{"repoURL":"https://charts.jetstack.io","chart":"cert-manager","namespace":"cert-manager"}}`)},
			},
		},
	}
}

func (f *fakeCatalog) GetItemByID(_ context.Context, id string) (*types.CatalogItem, error) {
	it, ok := f.items[id]
	if !ok {
		return nil, catalog.ErrItemNotFound
	}
	return it, nil
}

func (f *fakeCatalog) GetVersion(_ context.Context, itemID, version string) (*types.CatalogItemVersion, error) {
	for i, v := range f.versions[itemID] {
		if v.Version == version {
			return &f.versions[itemID][i], nil
		}
	}
	return nil, catalog.ErrVersionNotFound
}

func (f *fakeCatalog) ListVersions(_ context.Context, itemID string) ([]types.CatalogItemVersion, error) {
	return f.versions[itemID], nil
}

func (f *fakeCatalog) EffectiveVersion(_ context.Context, _, itemID, _ string) (string, error) {
	vers := f.versions[itemID]
	if len(vers) == 0 {
		return "", catalog.ErrVersionNotFound
	}
	return vers[len(vers)-1].Version, nil
}

type fakeClusters struct{ clusters []types.Cluster }

func (f *fakeClusters) GetCluster(_ context.Context, id string) (*types.Cluster, error) {
	for i := range f.clusters {
		if f.clusters[i].ID == id {
			return &f.clusters[i], nil
		}
	}
	return nil, errors.New("cluster not found")
}

func (f *fakeClusters) ListClusters(_ context.Context, orgID string) ([]types.Cluster, error) {
	var out []types.Cluster
	for _, c := range f.clusters {
		if c.OrgID == orgID {
			out = append(out, c)
		}
	}
	return out, nil
}

type fakeQueue struct{ cmds []types.AgentCommand }

func (f *fakeQueue) Enqueue(_ context.Context, cmd *types.AgentCommand) error {
	f.cmds = append(f.cmds, *cmd)
	return nil
}

// newTestService wires a DB-less addons service over fakes (audit nil →
// audit/outbox writes skipped).
func newTestService(store *fakeStore, cat *fakeCatalog, clusters *fakeClusters, git *gitprovider.Fake, queue *fakeQueue) *Service {
	resolver := gitprovider.NewRepoResolver(fakeRepoStoreAdapter{store}, nil, gitprovider.StaticResolver{P: git})
	return NewService(nil, store, cat, clusters, resolver, queue, nil)
}

func seedBaselineRepo(store *fakeStore, git *gitprovider.Fake, orgID, repo string, policy types.CommitPolicy) *types.TenantGitRepo {
	row := &types.TenantGitRepo{
		ID: "repo-baseline", OrgID: orgID, Name: "baseline", Repo: repo,
		Scope: types.GitRepoScopePlatform, CommitPolicy: policy, BaseBranch: "main", IsDefault: true,
	}
	store.repos[row.ID] = row
	store.baselines["c1"] = row.ID
	if _, err := git.EnsureRepo(context.Background(), repo); err != nil {
		panic(err)
	}
	return row
}

func activeCluster(id, orgID, name string, labels map[string]string) types.Cluster {
	return types.Cluster{ID: id, OrgID: orgID, Name: name, State: types.ClusterStateActive, Labels: labels}
}

// --- pure function tests ---------------------------------------------------

func TestValidateValues(t *testing.T) {
	schema := certManagerSchema
	if err := validateValues(schema, json.RawMessage(`{"crds":{"enabled":true},"replicaCount":2}`)); err != nil {
		t.Errorf("valid values rejected: %v", err)
	}
	err := validateValues(schema, json.RawMessage(`{"replicaCount":0}`))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("invalid values: want ValidationError, got %v", err)
	}
	if len(ve.Fields) == 0 {
		t.Error("expected field-level errors")
	}
	if err := validateValues(nil, json.RawMessage(`{"anything":true}`)); err != nil {
		t.Errorf("no schema must allow: %v", err)
	}
	// The object-shape requirement applies with or without a schema —
	// scalar/array values would otherwise 500 deep in the renderer.
	for _, raw := range []string{`"str"`, `[1,2]`, `42`, `true`} {
		if err := validateValues(nil, json.RawMessage(raw)); err == nil {
			t.Errorf("no schema: non-object values %s must be rejected", raw)
		}
		if err := validateValues(schema, json.RawMessage(raw)); err == nil {
			t.Errorf("schema: non-object values %s must be rejected", raw)
		}
	}
	if err := validateValues(nil, json.RawMessage(`null`)); err != nil {
		t.Errorf("null values = empty object: %v", err)
	}
	if err := validateValues(schema, json.RawMessage(`{nope`)); err == nil {
		t.Error("malformed JSON must be rejected")
	}
}

func TestMatchSelector(t *testing.T) {
	labels := map[string]string{"env": "prod", "region": "eu"}
	if !matchSelector(nil, labels) {
		t.Error("nil selector matches all")
	}
	if !matchSelector(map[string]string{"env": "prod"}, labels) {
		t.Error("subset selector must match")
	}
	if matchSelector(map[string]string{"env": "dev"}, labels) {
		t.Error("mismatch must not match")
	}
	if matchSelector(map[string]string{"env": "prod"}, nil) {
		t.Error("nil labels must not match a non-empty selector")
	}
}

func TestDescriptorFor(t *testing.T) {
	desc, _, err := descriptorFor("platform:cert-manager", &types.CatalogItemVersion{
		Version: "v1.16.2",
		Payload: json.RawMessage(`{"chart":{"repoURL":"https://charts.jetstack.io","chart":"cert-manager"}}`),
	})
	if err != nil || desc.Kind != types.SourceKindHelm || desc.Helm.Version != "v1.16.2" {
		t.Errorf("chart payload → helm descriptor, got %+v, %v", desc, err)
	}
	desc, _, err = descriptorFor("curated:pg", &types.CatalogItemVersion{Version: "1.0.0", Payload: json.RawMessage(`{"rgd":"spec: {}"}`)})
	if err != nil || desc.Kind != types.SourceKindKRO || desc.KRO.RGDRef != "curated:pg@1.0.0" {
		t.Errorf("rgd payload → kro descriptor, got %+v, %v", desc, err)
	}
	if _, _, err := descriptorFor("platform:empty", &types.CatalogItemVersion{Version: "1.0.0"}); !errors.Is(err, ErrNotDeployable) {
		t.Errorf("empty payload: want ErrNotDeployable, got %v", err)
	}
}

// A version bump must re-derive the source descriptor from the TARGET
// version's catalog payload: chart coordinates (repoURL/chart) may move
// between versions, and the stored source only carries the old ones.
func TestUpdatePicksUpTargetVersionCoordinates(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	cat.versions["platform:cert-manager"] = append(cat.versions["platform:cert-manager"],
		types.CatalogItemVersion{
			ItemID: "platform:cert-manager", Version: "v1.17.0", Channel: "stable",
			Schema:  certManagerSchema,
			Payload: json.RawMessage(`{"chart":{"repoURL":"https://charts.example.com/moved","chart":"cert-manager","namespace":"cert-manager"}}`),
		})
	clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod", nil)}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
	svc := newTestService(store, cat, clusters, git, queue)
	ctx := context.Background()

	res, err := svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v1.16.1"}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	newVersion := "v1.17.0"
	upd, err := svc.Update(ctx, "org:1", res.Addon.ID, UpdateInput{ChartVersion: &newVersion}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if got := upd.Addon.Source.Helm.RepoURL; got != "https://charts.example.com/moved" {
		t.Errorf("stored source repoURL = %q, want the target version's coordinates", got)
	}
	app := git.Files("acme/state", "main")["addons/cert-manager/application.yaml"]
	if !strings.Contains(app, "repoURL: https://charts.example.com/moved") ||
		!strings.Contains(app, "targetRevision: v1.17.0") {
		t.Errorf("re-rendered application must use the new version's coordinates:\n%s", app)
	}
}

func TestDecodeReportAddons(t *testing.T) {
	doc, err := structpb.NewStruct(map[string]any{
		"addons": []any{map[string]any{
			"catalogItem": "platform:cert-manager", "releaseName": "cert-manager",
			"namespace": "cert-manager", "detectedVersion": "v1.16.2",
			"chart": "cert-manager", "repoUrl": "https://charts.jetstack.io",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := anypb.New(doc)
	if err != nil {
		t.Fatal(err)
	}
	items, err := DecodeReportAddons(payload)
	if err != nil || len(items) != 1 {
		t.Fatalf("decode: %v, %d", err, len(items))
	}
	if items[0].CatalogItem != "platform:cert-manager" || items[0].DetectedVersion != "v1.16.2" {
		t.Errorf("unexpected item: %+v", items[0])
	}
	if _, err := DecodeReportAddons(nil); err == nil {
		t.Error("nil payload must fail")
	}
	other, _ := anypb.New(structpb.NewStringValue("x"))
	if _, err := DecodeReportAddons(other); err == nil {
		t.Error("non-struct payload must fail")
	}
}

// --- service flow tests ----------------------------------------------------

func TestAdoptApplicationDirectPolicy(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod-eu", nil)}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/acme-inari-state", types.CommitPolicyDirect)
	svc := newTestService(store, cat, clusters, git, queue)

	res, err := svc.Adopt(context.Background(), "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.2", Values: json.RawMessage(`{"crds":{"enabled":true}}`),
	}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if res.CommitSHA == "" || res.PRURL != "" {
		t.Errorf("direct policy: sha=%q pr=%q", res.CommitSHA, res.PRURL)
	}
	row := res.Addon
	if row.State != types.AddonStateManaged || row.RepoID != "repo-baseline" ||
		row.RepoPath != "addons/cert-manager" || row.ChartVersion != "v1.16.2" ||
		row.PruneEnabled || row.Namespace != "cert-manager" {
		t.Errorf("unexpected row: %+v", row)
	}
	if row.ArgoCDApp != "inari-addon-"+row.ID {
		t.Errorf("argocd app = %q", row.ArgoCDApp)
	}

	files := git.Files("acme/acme-inari-state", "main")
	app, ok := files["addons/cert-manager/application.yaml"]
	if !ok {
		t.Fatalf("application.yaml not committed; have %v", keysOf(files))
	}
	if !strings.Contains(app, "name: inari-addon-"+row.ID) {
		t.Error("application name mismatch")
	}
	if !strings.Contains(app, "prune: false") || !strings.Contains(app, "TakeOwnership=true") {
		t.Error("adoption must render prune OFF + take-ownership")
	}
	if !strings.Contains(app, "targetRevision: v1.16.2") {
		t.Error("chart version must be the application targetRevision")
	}
	vals := files["addons/cert-manager/values.yaml"]
	if !strings.Contains(vals, "enabled: true") {
		t.Errorf("values.yaml = %q", vals)
	}

	if len(queue.cmds) != 1 {
		t.Fatalf("expected 1 registration command, got %d", len(queue.cmds))
	}
	cmd := queue.cmds[0]
	// Application-mode addon registrations use the manifest bridge
	// (EVENT_TYPE_REGISTER_ARGOCD_APP_MANIFEST): the committed
	// application.yaml is upserted verbatim so multi-source helm apps and
	// TakeOwnership survive — RegisterArgoCDApp fields cannot express them.
	if cmd.ClusterID != "c1" || cmd.Type != RegisterAppManifestEventType {
		t.Errorf("unexpected command: %+v", cmd)
	}
	var appAny anypb.Any
	if err := protojson.Unmarshal(cmd.Payload, &appAny); err != nil {
		t.Fatalf("command payload is not protojson Any: %v", err)
	}
	var appBridge structpb.Struct
	if err := appAny.UnmarshalTo(&appBridge); err != nil {
		t.Fatalf("app bridge payload: %v", err)
	}
	if got := appBridge.Fields["commandId"].GetStringValue(); got != "inari-addon-"+row.ID {
		t.Errorf("bridge commandId = %q", got)
	}
	if got := appBridge.Fields["name"].GetStringValue(); got != "inari-addon-"+row.ID {
		t.Errorf("bridge name = %q", got)
	}
	manifest := appBridge.Fields["manifest"].GetStringValue()
	if manifest != app {
		t.Errorf("bridge manifest must be the committed application.yaml verbatim")
	}
}

func TestAdoptApplicationSet(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{
		activeCluster("c1", "org:1", "prod-eu", map[string]string{"env": "prod"}),
		activeCluster("c2", "org:1", "prod-us", map[string]string{"env": "prod"}),
		activeCluster("c3", "org:1", "dev", map[string]string{"env": "dev"}),
	}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/acme-inari-state", types.CommitPolicyDirect)
	svc := newTestService(store, cat, clusters, git, queue)

	res, err := svc.Adopt(context.Background(), "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.1", DeployMode: types.AddonDeployModeApplicationSet,
		ClusterSelector: map[string]string{"env": "prod"},
	}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	row := res.Addon
	if row.ClusterID != "*" || row.DeployMode != types.AddonDeployModeApplicationSet {
		t.Errorf("fleet row: %+v", row)
	}
	if row.ArgoCDApp != "inari-addonset-"+row.ID {
		t.Errorf("appset name = %q", row.ArgoCDApp)
	}
	files := git.Files("acme/acme-inari-state", "main")
	appset, ok := files["addons/cert-manager/applicationset.yaml"]
	if !ok {
		t.Fatalf("applicationset.yaml not committed; have %v", keysOf(files))
	}
	if !strings.Contains(appset, "cluster: prod-eu") || !strings.Contains(appset, "cluster: prod-us") {
		t.Error("list generator must contain both prod clusters")
	}
	if strings.Contains(appset, "cluster: dev") {
		t.Error("dev cluster must be excluded by the selector")
	}
	if !strings.Contains(appset, "inari-addon-"+row.ID+"-{{cluster}}") {
		t.Error("child app template name mismatch")
	}
	if len(queue.cmds) != 1 || queue.cmds[0].Type != RegisterAppSetEventType {
		t.Fatalf("expected appset registration command, got %+v", queue.cmds)
	}
	if queue.cmds[0].ClusterID != "c1" {
		t.Errorf("appset registration anchors on the adopting cluster, got %q", queue.cmds[0].ClusterID)
	}
	// The structpb bridge payload carries the rendered manifest verbatim.
	var cmdAny anypb.Any
	if err := protojson.Unmarshal(queue.cmds[0].Payload, &cmdAny); err != nil {
		t.Fatalf("command payload is not protojson Any: %v", err)
	}
	var bridge structpb.Struct
	if err := cmdAny.UnmarshalTo(&bridge); err != nil {
		t.Fatalf("appset bridge payload: %v", err)
	}
	if got := bridge.Fields["commandId"].GetStringValue(); got != "inari-addonset-"+row.ID {
		t.Errorf("bridge commandId = %q (agent echoes it for acks)", got)
	}
	if got := bridge.Fields["name"].GetStringValue(); got != "inari-addonset-"+row.ID {
		t.Errorf("bridge name = %q", got)
	}
	if got := bridge.Fields["namespace"].GetStringValue(); got != "argocd" {
		t.Errorf("bridge namespace = %q", got)
	}
	if got := bridge.Fields["manifest"].GetStringValue(); got != appset {
		t.Error("bridge manifest must be the committed applicationset.yaml verbatim")
	}

	// Empty selector fleet: no match → 422-class error.
	store2 := newFakeStore()
	seedBaselineRepo(store2, gitprovider.NewFake(), "org:1", "acme/x", types.CommitPolicyDirect)
	svc2 := newTestService(store2, cat, clusters, gitprovider.NewFake(), &fakeQueue{})
	if _, err := svc2.Adopt(context.Background(), "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.1", DeployMode: types.AddonDeployModeApplicationSet,
		ClusterSelector: map[string]string{"env": "nonexistent"},
	}, "user:u1"); !errors.Is(err, ErrEmptyFleet) {
		t.Errorf("empty fleet: want ErrEmptyFleet, got %v", err)
	}
}

func TestFleetAdoptAbsorbsDiscoveredRows(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{
		activeCluster("c1", "org:1", "prod-eu", map[string]string{"env": "prod"}),
		activeCluster("c2", "org:1", "prod-us", map[string]string{"env": "prod"}),
	}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
	svc := newTestService(store, cat, clusters, git, queue)
	ctx := context.Background()

	// The scanner saw cert-manager on both clusters before adoption.
	for _, c := range []string{"c1", "c2"} {
		if err := svc.IngestDiscovery(ctx, "org:1", c, []DiscoveredAddon{{
			CatalogItem: "platform:cert-manager", ReleaseName: "cert-manager",
			Namespace: "cert-manager", DetectedVersion: "v1.16.0",
		}}); err != nil {
			t.Fatal(err)
		}
	}

	res, err := svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.1", DeployMode: types.AddonDeployModeApplicationSet,
		ClusterSelector: map[string]string{"env": "prod"},
	}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}

	// Both per-cluster discovered rows are absorbed; the scan evidence
	// moves into the fleet row's discovered_meta.
	for _, c := range []string{"c1", "c2"} {
		if _, err := store.GetClusterAddon(ctx, nil, "org:1", c, "platform:cert-manager"); !errors.Is(err, inventory.ErrAddonNotFound) {
			t.Errorf("%s discovered row should be absorbed, got %v", c, err)
		}
	}
	if !strings.Contains(string(res.Addon.DiscoveredMeta), "absorbedSightings") {
		t.Errorf("fleet row discovered_meta = %s, want absorbed sightings", res.Addon.DiscoveredMeta)
	}

	// The scanner reporting the release again must not recreate a
	// discovered row for a fleet-managed item.
	if err := svc.IngestDiscovery(ctx, "org:1", "c2", []DiscoveredAddon{{
		CatalogItem: "platform:cert-manager", ReleaseName: "cert-manager", DetectedVersion: "v1.16.0",
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetClusterAddon(ctx, nil, "org:1", "c2", "platform:cert-manager"); !errors.Is(err, inventory.ErrAddonNotFound) {
		t.Errorf("post-adopt discovery should be skipped, got %v", err)
	}
}

func TestAdoptPullRequestPolicy(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod", nil)}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyPullRequest)
	svc := newTestService(store, cat, clusters, git, queue)

	res, err := svc.Adopt(context.Background(), "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v1.16.1"}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if res.PRURL == "" {
		t.Fatal("PR policy must open a PR")
	}
	if len(git.PRs) != 1 || len(git.PRs[0].Files) != 2 {
		t.Errorf("PR files: %+v", git.PRs)
	}
	// The PR-merge registration gap (documented): no command until merge.
	if len(queue.cmds) != 0 {
		t.Errorf("PR policy must not enqueue registration, got %+v", queue.cmds)
	}
	if res.Addon.PRURL != res.PRURL || res.Addon.State != types.AddonStateManaged {
		t.Errorf("row: %+v", res.Addon)
	}
}

func TestAdoptValidationAndConflicts(t *testing.T) {
	newSvc := func() (*Service, *fakeStore) {
		store, cat := newFakeStore(), newFakeCatalog()
		clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod", nil)}}
		git := gitprovider.NewFake()
		seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
		return newTestService(store, cat, clusters, git, &fakeQueue{}), store
	}

	// Invalid values → ValidationError, nothing committed.
	svc, _ := newSvc()
	_, err := svc.Adopt(context.Background(), "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.1", Values: json.RawMessage(`{"replicaCount":0}`),
	}, "user:u1")
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}

	// Adopting twice → ErrAlreadyManaged.
	svc, store := newSvc()
	if _, err := svc.Adopt(context.Background(), "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v1.16.1"}, "user:u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Adopt(context.Background(), "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v1.16.2"}, "user:u1"); !errors.Is(err, ErrAlreadyManaged) {
		t.Errorf("re-adopt: want ErrAlreadyManaged, got %v", err)
	}
	_ = store

	// Unknown catalog version → catalog sentinel.
	svc, _ = newSvc()
	if _, err := svc.Adopt(context.Background(), "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v9.9.9"}, "user:u1"); !errors.Is(err, catalog.ErrVersionNotFound) {
		t.Errorf("unknown version: want ErrVersionNotFound, got %v", err)
	}

	// Unknown catalog item → catalog sentinel.
	svc, _ = newSvc()
	if _, err := svc.Adopt(context.Background(), "org:1", "c1", "platform:missing", AdoptInput{}, "user:u1"); !errors.Is(err, catalog.ErrItemNotFound) {
		t.Errorf("unknown item: want ErrItemNotFound, got %v", err)
	}
}

func TestAdoptPreservesDiscoveredRowID(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod", nil)}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
	svc := newTestService(store, cat, clusters, git, queue)

	if err := svc.IngestDiscovery(context.Background(), "org:1", "c1", []DiscoveredAddon{{
		CatalogItem: "platform:cert-manager", ReleaseName: "cert-manager",
		Namespace: "cert-manager", DetectedVersion: "v1.15.0", Chart: "cert-manager",
	}}); err != nil {
		t.Fatal(err)
	}
	discovered := store.addons[addonKey("c1", "platform:cert-manager")]
	if discovered.State != types.AddonStateDiscovered || discovered.ChartVersion != "v1.15.0" {
		t.Fatalf("discovery row: %+v", discovered)
	}

	res, err := svc.Adopt(context.Background(), "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v1.16.1"}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Addon.ID != discovered.ID {
		t.Errorf("adopt must preserve the discovered row ID %q, got %q", discovered.ID, res.Addon.ID)
	}
	if len(res.Addon.DiscoveredMeta) == 0 {
		t.Error("discovered_meta must survive adoption")
	}

	// A discovery re-report must not downgrade the managed row.
	if err := svc.IngestDiscovery(context.Background(), "org:1", "c1", []DiscoveredAddon{{
		CatalogItem: "platform:cert-manager", DetectedVersion: "v1.15.0", Chart: "cert-manager",
	}}); err != nil {
		t.Fatal(err)
	}
	got := store.addons[addonKey("c1", "platform:cert-manager")]
	if got.State != types.AddonStateManaged || got.ChartVersion != "v1.16.1" {
		t.Errorf("discovery overwrote managed row: %+v", got)
	}
}

func TestUpdateVersionAndValues(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod", nil)}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
	svc := newTestService(store, cat, clusters, git, queue)
	ctx := context.Background()

	res, err := svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v1.16.1"}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	id := res.Addon.ID
	newVersion := "v1.16.2"
	upd, err := svc.Update(ctx, "org:1", id, UpdateInput{
		ChartVersion: &newVersion,
		Values:       rawMsg(`{"crds":{"enabled":false}}`),
	}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if upd.Addon.ChartVersion != "v1.16.2" || upd.CommitSHA == "" {
		t.Errorf("update result: %+v", upd)
	}
	app := git.Files("acme/state", "main")["addons/cert-manager/application.yaml"]
	if !strings.Contains(app, "targetRevision: v1.16.2") {
		t.Error("re-rendered application must pin the new chart version")
	}
	vals := git.Files("acme/state", "main")["addons/cert-manager/values.yaml"]
	if !strings.Contains(vals, "enabled: false") {
		t.Errorf("values.yaml = %q", vals)
	}
	// Update re-registers the app (direct policy).
	if len(queue.cmds) != 2 {
		t.Errorf("adopt+update commands = %d", len(queue.cmds))
	}

	// Stored values are re-validated against the new version's schema:
	// replicaCount 0 violates minimum:1 in v1.16.2's schema.
	bad := "v1.16.2"
	badValues := json.RawMessage(`{"replicaCount":0}`)
	if _, err := svc.Update(ctx, "org:1", id, UpdateInput{ChartVersion: &bad, Values: &badValues}, "user:u1"); err == nil {
		t.Error("schema-invalid values must be rejected")
	} else {
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("want ValidationError, got %v", err)
		}
	}
	// The failed validation must not have touched git.
	if strings.Contains(git.Files("acme/state", "main")["addons/cert-manager/values.yaml"], "replicaCount") {
		t.Error("rejected update must not commit")
	}

	// Not-managed rows reject updates.
	if _, err := svc.Update(ctx, "org:1", "missing", UpdateInput{ChartVersion: &bad}, "user:u1"); !errors.Is(err, inventory.ErrAddonNotFound) {
		t.Errorf("unknown addon: want ErrAddonNotFound, got %v", err)
	}
}

// Version bumps re-validate the STORED values against the new chart
// version's schema (decision 4): values legal under v1.16.1 but illegal
// under v1.16.2 reject the bump with field-level errors, before any git
// write.
func TestVersionBumpRevalidatesStoredValues(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	// v1.16.2 tightens the schema: replicaCount minimum moves 1 → 2.
	strictSchema := json.RawMessage(`{"type":"object","properties":{"replicaCount":{"type":"integer","minimum":2}}}`)
	cat.versions["platform:cert-manager"][1].Schema = strictSchema

	clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod", nil)}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
	svc := newTestService(store, cat, clusters, git, queue)
	ctx := context.Background()

	res, err := svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.1", Values: json.RawMessage(`{"replicaCount":1}`),
	}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	id := res.Addon.ID

	bump := "v1.16.2"
	_, err = svc.Update(ctx, "org:1", id, UpdateInput{ChartVersion: &bump}, "user:u1")
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("bump with now-invalid stored values: want ValidationError, got %v", err)
	}
	if len(ve.Fields) == 0 || ve.Fields[0].Path == "" {
		t.Errorf("field-level errors required, got %+v", ve)
	}
	// The rejection is pre-commit: git and the row stay on the old version.
	app := git.Files("acme/state", "main")["addons/cert-manager/application.yaml"]
	if !strings.Contains(app, "targetRevision: v1.16.1") {
		t.Error("rejected bump must not rewrite the committed application")
	}
	row, err := store.GetClusterAddonByID(ctx, nil, "org:1", id)
	if err != nil {
		t.Fatal(err)
	}
	if row.ChartVersion != "v1.16.1" {
		t.Errorf("row version = %q, want unchanged v1.16.1", row.ChartVersion)
	}

	// Supplying conforming values with the bump succeeds.
	okValues := json.RawMessage(`{"replicaCount":2}`)
	upd, err := svc.Update(ctx, "org:1", id, UpdateInput{ChartVersion: &bump, Values: &okValues}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if upd.Addon.ChartVersion != "v1.16.2" {
		t.Errorf("version = %q", upd.Addon.ChartVersion)
	}
}

func TestEnablePrune(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod", nil)}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
	svc := newTestService(store, cat, clusters, git, queue)
	ctx := context.Background()

	res, err := svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v1.16.1"}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	id := res.Addon.ID
	pr, err := svc.EnablePrune(ctx, "org:1", id, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if !pr.Addon.PruneEnabled {
		t.Error("prune_enabled must be set")
	}
	app := git.Files("acme/state", "main")["addons/cert-manager/application.yaml"]
	if !strings.Contains(app, "prune: true") {
		t.Error("re-rendered application must enable prune")
	}
	// The re-registered app carries the re-rendered manifest with prune on.
	last := queue.cmds[len(queue.cmds)-1]
	if last.Type != RegisterAppManifestEventType || !strings.Contains(string(last.Payload), "prune: true") {
		t.Errorf("re-registration payload: %s", last.Payload)
	}
	if _, err := svc.EnablePrune(ctx, "org:1", id, "user:u1"); !errors.Is(err, ErrPruneAlreadyEnabled) {
		t.Errorf("second enable-prune: want ErrPruneAlreadyEnabled, got %v", err)
	}
}

func TestListTeamFilteringAndVersions(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod", nil)}}
	git := gitprovider.NewFake()
	baseline := seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
	teamRepo := &types.TenantGitRepo{
		ID: "repo-team-a", OrgID: "org:1", Name: "team-a", Repo: "acme/team-a",
		Scope: types.GitRepoScopeTeam, TeamID: "team-a-id", CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main",
	}
	store.repos[teamRepo.ID] = teamRepo
	svc := newTestService(store, cat, clusters, git, &fakeQueue{})
	ctx := context.Background()

	// Discovered addon (no repo) + managed addon on the baseline + managed
	// addon on team-a's repo.
	if err := svc.IngestDiscovery(ctx, "org:1", "c1", []DiscoveredAddon{{CatalogItem: "platform:cert-manager", Chart: "cert-manager"}}); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v1.16.1"}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	_ = baseline
	store.addons[addonKey("c1", "platform:external-secrets")] = &types.ClusterAddon{
		ID: "addon-eso", OrgID: "org:1", ClusterID: "c1", CatalogItem: "platform:external-secrets",
		State: types.AddonStateManaged, RepoID: teamRepo.ID, RepoPath: "addons/external-secrets",
		Source: types.SourceDescriptor{Kind: types.SourceKindHelm, Helm: &types.HelmSource{RepoURL: "r", Chart: "c", Version: "v1"}},
	}

	// Privileged (nil filter) sees both + available versions.
	all, err := svc.List(ctx, "org:1", "c1", nil)
	if err != nil || len(all) != 2 {
		t.Fatalf("privileged list = %d, %v", len(all), err)
	}
	for _, a := range all {
		if a.CatalogItem == "platform:cert-manager" {
			if len(a.AvailableVersions) != 2 {
				t.Errorf("cert-manager versions = %v", a.AvailableVersions)
			}
			if a.PruneEnabled {
				t.Error("prune off after adopt")
			}
		}
	}
	// team-b member sees the baseline-managed addon but not team-a's.
	filtered, err := svc.List(ctx, "org:1", "c1", []string{"team-b-id"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range filtered {
		if a.RepoID == teamRepo.ID {
			t.Errorf("team-b must not see team-a repo addon: %+v", a)
		}
	}
	if len(filtered) != 1 {
		t.Errorf("team-b list = %d, want 1 (baseline addon; discovered row was adopted)", len(filtered))
	}
	// team-a member sees both.
	ta, err := svc.List(ctx, "org:1", "c1", []string{"team-a-id"})
	if err != nil || len(ta) != 2 {
		t.Errorf("team-a list = %d, %v", len(ta), err)
	}
	_ = res
}

func TestListIncludesSelectorMatchedFleetRows(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{
		activeCluster("c1", "org:1", "prod-eu", map[string]string{"env": "prod"}),
		activeCluster("c2", "org:1", "dev-eu", map[string]string{"env": "dev"}),
	}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
	svc := newTestService(store, cat, clusters, git, queue)
	ctx := context.Background()

	// Fleet-wide addon targeting env=prod (adopted from a prod cluster).
	if _, err := svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.1", DeployMode: types.AddonDeployModeApplicationSet,
		ClusterSelector: map[string]string{"env": "prod"},
	}, "user:u1"); err != nil {
		t.Fatal(err)
	}

	// The targeted cluster lists the fleet addon (badged by clusterId "*",
	// with the version dropdown populated like any managed row).
	prod, err := svc.List(ctx, "org:1", "c1", nil)
	if err != nil || len(prod) != 1 {
		t.Fatalf("prod list = %d, %v", len(prod), err)
	}
	if prod[0].ClusterID != "*" || prod[0].DeployMode != types.AddonDeployModeApplicationSet {
		t.Errorf("fleet row = cluster %q mode %q", prod[0].ClusterID, prod[0].DeployMode)
	}
	if len(prod[0].AvailableVersions) != 2 {
		t.Errorf("fleet row versions = %v", prod[0].AvailableVersions)
	}

	// A cluster outside the selector does not list it.
	dev, err := svc.List(ctx, "org:1", "c2", nil)
	if err != nil || len(dev) != 0 {
		t.Errorf("dev list = %d, %v (fleet selector must not match env=dev)", len(dev), err)
	}
}

func TestFleetReconcilerRerendersOnMembershipChange(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{
		activeCluster("c1", "org:1", "prod-eu", map[string]string{"env": "prod"}),
	}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
	svc := newTestService(store, cat, clusters, git, queue)
	ctx := context.Background()

	if _, err := svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.1", DeployMode: types.AddonDeployModeApplicationSet,
		ClusterSelector: map[string]string{"env": "prod"},
	}, "user:u1"); err != nil {
		t.Fatal(err)
	}
	baseline1 := git.Files("acme/state", "main")["addons/cert-manager/applicationset.yaml"]
	if strings.Contains(baseline1, "prod-us") {
		t.Fatal("precondition: one element")
	}

	reconciler := NewFleetReconciler(svc, nil)

	// A new cluster matching the selector registers → re-render + commit.
	clusters.clusters = append(clusters.clusters, activeCluster("c2", "org:1", "prod-us", map[string]string{"env": "prod"}))
	ev := &types.OutboxEvent{Payload: json.RawMessage(`{"orgId":"org:1","clusterId":"c2","name":"prod-us"}`)}
	if err := reconciler.Handle(ctx, ev); err != nil {
		t.Fatal(err)
	}
	updated := git.Files("acme/state", "main")["addons/cert-manager/applicationset.yaml"]
	if !strings.Contains(updated, "cluster: prod-us") {
		t.Error("fleet re-render must add the new cluster to the list generator")
	}

	// A second identical event is a no-op (no new commit).
	commitsBefore := len(git.Files("acme/state", "main"))
	if err := reconciler.Handle(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// Fake records a commit per CommitFiles call; unchanged content skips.
	if got := len(git.Files("acme/state", "main")); got != commitsBefore {
		t.Errorf("idempotent reconcile changed files: %d → %d", commitsBefore, got)
	}

	// An unrelated org's event does nothing.
	other := &types.OutboxEvent{Payload: json.RawMessage(`{"orgId":"org:2","clusterId":"c9"}`)}
	if err := reconciler.Handle(ctx, other); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateFailureMarksUpdateFailed(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod", nil)}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	repo := seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
	svc := newTestService(store, cat, clusters, git, queue)
	ctx := context.Background()

	res, err := svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v1.16.1"}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	// Break the git target (repo vanished from the host): the update must
	// fail AND flip the row to update_failed.
	repo.Repo = "acme/gone"
	if _, err := svc.Update(ctx, "org:1", res.Addon.ID, UpdateInput{Values: rawMsg(`{"crds":{"enabled":false}}`)}, "user:u1"); err == nil {
		t.Fatal("expected git write failure")
	}
	got, _ := store.GetClusterAddonByID(ctx, nil, "org:1", res.Addon.ID)
	if got.State != types.AddonStateUpdateFailed {
		t.Errorf("state = %q, want update_failed", got.State)
	}
	// A subsequent fixed update recovers to managed.
	repo.Repo = "acme/state"
	if _, err := svc.Update(ctx, "org:1", res.Addon.ID, UpdateInput{Values: rawMsg(`{"crds":{"enabled":true}}`)}, "user:u1"); err != nil {
		t.Fatal(err)
	}
	got, _ = store.GetClusterAddonByID(ctx, nil, "org:1", res.Addon.ID)
	if got.State != types.AddonStateManaged {
		t.Errorf("recovered state = %q", got.State)
	}
}

func rawMsg(s string) *json.RawMessage {
	m := json.RawMessage(s)
	return &m
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- concurrency probes -----------------------------------------------------

// barrierStore synchronizes two concurrent claimers so BOTH arrive at the
// adopt claim before either proceeds — deterministically exercising the
// claim's atomicity (pre-fix, the check-then-act read raced here and both
// adopts won).
type barrierStore struct {
	*fakeStore
	mu       sync.Mutex
	waiting  int
	release  chan struct{}
	claimKey string
}

func (b *barrierStore) ClaimClusterAddonForAdoption(ctx context.Context, q db.Querier, a *types.ClusterAddon) (string, json.RawMessage, bool, bool, error) {
	if a.ClusterID+"|"+a.CatalogItem == b.claimKey {
		b.mu.Lock()
		b.waiting++
		if b.waiting == 2 {
			close(b.release)
		}
		b.mu.Unlock()
		<-b.release
	}
	return b.fakeStore.ClaimClusterAddonForAdoption(ctx, q, a)
}

// Two concurrent adopts of the same item on the same cluster must produce
// exactly one winner; the loser must get ErrAlreadyManaged. A double win
// double-commits and registers two ArgoCD apps for one row.
func TestConcurrentAdoptClaimsOnce(t *testing.T) {
	base := newFakeStore()
	store := &barrierStore{fakeStore: base, release: make(chan struct{}), claimKey: "c1|platform:cert-manager"}
	cat := newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod", nil)}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(base, git, "org:1", "acme/state", types.CommitPolicyDirect)
	resolver := gitprovider.NewRepoResolver(fakeRepoStoreAdapter{base}, nil, gitprovider.StaticResolver{P: git})
	svc := NewService(nil, store, cat, clusters, resolver, queue, nil)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v1.16.1"}, "user:u1")
		}(i)
	}
	wg.Wait()

	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrAlreadyManaged):
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Errorf("concurrent adopts: %d winners, want exactly 1 (errs %v)", wins, errs)
	}
}

// Delete orphans the row in ANY state — including a stranded adopting
// placeholder (the escape hatch for a crashed adopt).
func TestDeleteAddon(t *testing.T) {
	store, cat := newFakeStore(), newFakeCatalog()
	clusters := &fakeClusters{clusters: []types.Cluster{activeCluster("c1", "org:1", "prod", nil)}}
	git, queue := gitprovider.NewFake(), &fakeQueue{}
	seedBaselineRepo(store, git, "org:1", "acme/state", types.CommitPolicyDirect)
	svc := newTestService(store, cat, clusters, git, queue)
	ctx := context.Background()

	res, err := svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v1.16.1"}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, "org:1", res.Addon.ID, "user:u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetClusterAddonByID(ctx, nil, "org:1", res.Addon.ID); !errors.Is(err, inventory.ErrAddonNotFound) {
		t.Errorf("deleted row still present: %v", err)
	}
	// Orphan semantics: the git files and the registration stay untouched.
	if len(git.Files("acme/state", "main")) == 0 {
		t.Error("orphan delete must not touch git")
	}

	// A stranded adopting row is deletable (crashed-adopt escape hatch).
	store.addons[addonKey("c1", "platform:external-secrets")] = &types.ClusterAddon{
		ID: "addon-stuck", OrgID: "org:1", ClusterID: "c1", CatalogItem: "platform:external-secrets",
		State: types.AddonStateAdopting,
	}
	if err := svc.Delete(ctx, "org:1", "addon-stuck", "user:u1"); err != nil {
		t.Errorf("delete stranded adopting row: %v", err)
	}

	// Unknown IDs and foreign orgs 404.
	if err := svc.Delete(ctx, "org:1", "addon-nope", "user:u1"); !errors.Is(err, inventory.ErrAddonNotFound) {
		t.Errorf("unknown: want ErrAddonNotFound, got %v", err)
	}
	store.addons[addonKey("c9", "platform:cert-manager")] = &types.ClusterAddon{
		ID: "addon-other-org", OrgID: "org:2", ClusterID: "c9", CatalogItem: "platform:cert-manager",
		State: types.AddonStateManaged,
	}
	if err := svc.Delete(ctx, "org:1", "addon-other-org", "user:u1"); !errors.Is(err, inventory.ErrAddonNotFound) {
		t.Errorf("cross-org delete: want ErrAddonNotFound, got %v", err)
	}
}
