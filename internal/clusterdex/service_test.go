package clusterdex

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// --- fakes ---

type fakeClusters struct{ list []types.Cluster }

func (f fakeClusters) ListClusters(context.Context, string) ([]types.Cluster, error) {
	return f.list, nil
}

type fakeTeams struct{ list []types.Team }

func (f fakeTeams) ListTeams(context.Context, string) ([]types.Team, error) { return f.list, nil }

type fakeBaselines struct{ byCluster map[string]string }

func (f fakeBaselines) BaselineRepoSelector(_ context.Context, _ db.Querier, _, clusterID string) (string, error) {
	return f.byCluster[clusterID], nil
}

type fakeRepoLister struct{ repos []*types.TenantGitRepo }

func (f fakeRepoLister) ListGitRepos(context.Context, db.Querier, string, []string) ([]*types.TenantGitRepo, error) {
	return f.repos, nil
}

type fakeRepoStore struct {
	byID map[string]*types.TenantGitRepo
	def  *types.TenantGitRepo
}

func (f fakeRepoStore) GetGitRepo(_ context.Context, _, id string) (*types.TenantGitRepo, error) {
	if r, ok := f.byID[id]; ok {
		return r, nil
	}
	return nil, errors.New("repo not found")
}

func (f fakeRepoStore) GetDefaultGitRepo(context.Context, string) (*types.TenantGitRepo, error) {
	if f.def == nil {
		return nil, errors.New("no default repo")
	}
	return f.def, nil
}

// captureQueue mimics the real queue's idempotency: same row ID = no-op.
type captureQueue struct {
	seen map[string]bool
	cmds []types.AgentCommand
}

func (q *captureQueue) Enqueue(_ context.Context, cmd *types.AgentCommand) error {
	if q.seen == nil {
		q.seen = map[string]bool{}
	}
	if q.seen[cmd.ID] {
		return nil
	}
	q.seen[cmd.ID] = true
	q.cmds = append(q.cmds, *cmd)
	return nil
}

func testConfig() Config {
	return Config{
		PlatformChartRepoURL: "oci://ghcr.io/7k-inari/charts",
		PlatformChartName:    "inari-platform",
		PlatformChartVersion: "0.4.1",
		ESOSecretStore:       "vault-platform",
	}
}

type fixture struct {
	svc      *Service
	git      *gitprovider.Fake
	queue    *captureQueue
	repo     *types.TenantGitRepo
	clusters *fakeClusters
}

func newFixture(t *testing.T, clusters []types.Cluster, teams []types.Team) *fixture {
	t.Helper()
	repo := &types.TenantGitRepo{
		ID: "repo-1", OrgID: "org:1", Name: "baseline", Repo: "acme/acme-inari-state",
		Scope: types.GitRepoScopePlatform, CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main", IsDefault: true,
	}
	fake := gitprovider.NewFake()
	if _, err := fake.EnsureRepo(context.Background(), repo.Repo); err != nil {
		t.Fatal(err)
	}
	bindings := map[string]string{}
	for _, c := range clusters {
		bindings[c.ID] = repo.ID
	}
	queue := &captureQueue{}
	resolver := gitprovider.NewRepoResolver(fakeRepoStore{byID: map[string]*types.TenantGitRepo{repo.ID: repo}, def: repo}, nil, gitprovider.StaticResolver{P: fake})
	fc := &fakeClusters{list: clusters}
	svc := NewService(nil, testConfig(), fc, fakeTeams{list: teams}, fakeBaselines{byCluster: bindings},
		fakeRepoLister{repos: []*types.TenantGitRepo{repo}}, resolver, queue, nil, nil)
	return &fixture{svc: svc, git: fake, queue: queue, repo: repo, clusters: fc}
}

func cluster(id, name string, labels map[string]string) types.Cluster {
	return types.Cluster{ID: id, OrgID: "org:1", Name: name, Labels: labels, State: types.ClusterStateActive}
}

// --- tests ---

func TestRerenderOrgCommitsBothAppSets(t *testing.T) {
	f := newFixture(t, []types.Cluster{
		cluster("c1", "prod-eu", nil),
		cluster("c2", "prod-us", nil),
	}, []types.Team{
		{RoleName: "admin", KeycloakGroupPath: "/tenant-acme/platform-team"},
		{RoleName: "viewer", KeycloakGroupPath: "/tenant-acme/viewers"},
	})
	if err := f.svc.RerenderOrg(context.Background(), "org:1"); err != nil {
		t.Fatal(err)
	}
	files := f.git.Files("acme/acme-inari-state", "main")

	dexSet, ok := files["dex/applicationset.yaml"]
	if !ok {
		t.Fatalf("dex appset missing: %v", keysOf(files))
	}
	for _, want := range []string{
		"kind: ApplicationSet", "name: inari-addonset-dex",
		"chart: dex", "repoURL: https://charts.dexidp.io", "targetRevision: 0.25.2",
		"cluster: prod-eu", "cluster: prod-us",
		"clusterID: c1", "clusterID: c2",
		"dexAppName: dex-c1", "dexAppName: dex-c2",
		"name: '{{dexAppName}}'",
		"resources-finalizer.argocd.argoproj.io",
		"prune: true", "CreateNamespace=true",
		"namespace: dex",
		"https://github.com/acme/acme-inari-state",
		"$values/clusters/{{cluster}}/dex/values.yaml",
	} {
		if !strings.Contains(dexSet, want) {
			t.Errorf("dex appset missing %q:\n%s", want, dexSet)
		}
	}

	argoSet, ok := files["argocd-config/applicationset.yaml"]
	if !ok {
		t.Fatalf("argocd-config appset missing: %v", keysOf(files))
	}
	for _, want := range []string{
		"chart: inari-platform", "repoURL: oci://ghcr.io/7k-inari/charts", "targetRevision: 0.4.1",
		"name: argocd-config-{{cluster}}",
	} {
		if !strings.Contains(argoSet, want) {
			t.Errorf("argocd-config appset missing %q:\n%s", want, argoSet)
		}
	}

	base := files["dex/values.yaml"]
	for _, want := range []string{"networkPolicy:", "podDisruptionBudget:", "seccompProfile", "runAsNonRoot: true", "port: 5556"} {
		if !strings.Contains(base, want) {
			t.Errorf("dex base values missing %q:\n%s", want, base)
		}
	}
	if strings.Contains(base, "fullnameOverride") || strings.Contains(base, "configSecret") {
		t.Errorf("base values must not carry per-cluster keys:\n%s", base)
	}

	argoBase := files["argocd-config/values.yaml"]
	for _, want := range []string{"enabled: false", "enabled: true", "namespace: argocd"} {
		if !strings.Contains(argoBase, want) {
			t.Errorf("argocd-config base values missing %q:\n%s", want, argoBase)
		}
	}

	// Per-cluster overlays.
	dexOv := files["clusters/prod-eu/dex/values.yaml"]
	if !strings.Contains(dexOv, "fullnameOverride: dex-c1") || !strings.Contains(dexOv, "name: dex-config") {
		t.Errorf("dex overlay:\n%s", dexOv)
	}
	argoOv := files["clusters/prod-us/argocd-config/values.yaml"]
	for _, want := range []string{
		"issuerUrl: http://dex-c2.dex.svc.cluster.local:5556/dex",
		"name: argocd-dex-client",
		"/tenant-acme/platform-team", "/tenant-acme/viewers",
		"vaultPath: inari/clusters/c2/oidc-client-secret",
		"secretStore: vault-platform",
	} {
		if !strings.Contains(argoOv, want) {
			t.Errorf("argocd overlay missing %q:\n%s", want, argoOv)
		}
	}
}

func TestRerenderOrgDeliversPerClusterViews(t *testing.T) {
	f := newFixture(t, []types.Cluster{
		cluster("c1", "prod-eu", nil),
		cluster("c2", "prod-us", nil),
	}, nil)
	if err := f.svc.RerenderOrg(context.Background(), "org:1"); err != nil {
		t.Fatal(err)
	}
	// 2 clusters x 2 appsets.
	if len(f.queue.cmds) != 4 {
		t.Fatalf("commands = %d, want 4", len(f.queue.cmds))
	}
	byCluster := map[string][]types.AgentCommand{}
	for _, cmd := range f.queue.cmds {
		if cmd.Type != "EVENT_TYPE_REGISTER_ARGOCD_APPSET" {
			t.Errorf("type = %q", cmd.Type)
		}
		byCluster[cmd.ClusterID] = append(byCluster[cmd.ClusterID], cmd)
	}
	for cid, cmds := range byCluster {
		if len(cmds) != 2 {
			t.Errorf("%s: commands = %d, want 2", cid, len(cmds))
		}
		for _, cmd := range cmds {
			manifest := bridgeManifest(t, cmd)
			// Per-cluster view: exactly one element, and it is this cluster's.
			if strings.Count(manifest, "cluster: prod-") != 1 {
				t.Errorf("%s: manifest must carry exactly one element:\n%s", cid, manifest)
			}
			wantName := "prod-eu"
			if cid == "c2" {
				wantName = "prod-us"
			}
			if !strings.Contains(manifest, "cluster: "+wantName) {
				t.Errorf("%s: manifest must target %s:\n%s", cid, wantName, manifest)
			}
		}
	}
}

func TestRerenderOrgIdempotent(t *testing.T) {
	f := newFixture(t, []types.Cluster{cluster("c1", "prod-eu", nil)}, nil)
	ctx := context.Background()
	if err := f.svc.RerenderOrg(ctx, "org:1"); err != nil {
		t.Fatal(err)
	}
	before := f.git.Files("acme/acme-inari-state", "main")
	cmds := len(f.queue.cmds)
	if err := f.svc.RerenderOrg(ctx, "org:1"); err != nil {
		t.Fatal(err)
	}
	after := f.git.Files("acme/acme-inari-state", "main")
	if len(before) != len(after) {
		t.Errorf("file count changed: %d -> %d", len(before), len(after))
	}
	for p, c := range before {
		if after[p] != c {
			t.Errorf("%s changed on idempotent re-render", p)
		}
	}
	if len(f.queue.cmds) != cmds {
		t.Errorf("commands redelivered: %d -> %d", cmds, len(f.queue.cmds))
	}
}

func TestRerenderOrgOptOutDrains(t *testing.T) {
	f := newFixture(t, []types.Cluster{cluster("c1", "prod-eu", nil)}, nil)
	ctx := context.Background()
	if err := f.svc.RerenderOrg(ctx, "org:1"); err != nil {
		t.Fatal(err)
	}
	if f.git.Files("acme/acme-inari-state", "main")["clusters/prod-eu/dex/values.yaml"] == "" {
		t.Fatal("overlay must exist after first render")
	}

	// Opt the cluster out and re-render.
	f.clusters.list = []types.Cluster{cluster("c1", "prod-eu", map[string]string{DisabledLabel: DisabledLabelValue})}
	if err := f.svc.RerenderOrg(ctx, "org:1"); err != nil {
		t.Fatal(err)
	}
	files := f.git.Files("acme/acme-inari-state", "main")
	// The appset stays (empty elements = drain), the overlay is purged.
	dexSet := files["dex/applicationset.yaml"]
	if dexSet == "" {
		t.Fatal("appset must remain (empty elements) after opt-out")
	}
	if strings.Contains(dexSet, "prod-eu") {
		t.Errorf("opted-out cluster must leave the elements list:\n%s", dexSet)
	}
	if files["clusters/prod-eu/dex/values.yaml"] != "" {
		t.Error("stale overlay must be purged")
	}
	// The opted-out cluster receives the empty view (drain delivery).
	var drain *types.AgentCommand
	for i := range f.queue.cmds {
		if f.queue.cmds[i].ClusterID == "c1" && strings.Contains(bridgeManifest(t, f.queue.cmds[i]), "elements: []") {
			drain = &f.queue.cmds[i]
		}
	}
	if drain == nil {
		t.Errorf("no empty-view drain command for the opted-out cluster: %+v", f.queue.cmds)
	}
}

func TestRerenderOrgEmptyFleetNoPriorContent(t *testing.T) {
	f := newFixture(t, nil, nil)
	if err := f.svc.RerenderOrg(context.Background(), "org:1"); err != nil {
		t.Fatal(err)
	}
	if files := f.git.Files("acme/acme-inari-state", "main"); len(files) != 0 {
		t.Errorf("never-managed repo must stay untouched: %v", keysOf(files))
	}
	if len(f.queue.cmds) != 0 {
		t.Errorf("no deliveries expected: %v", f.queue.cmds)
	}
}

func TestRerenderOrgDeletesStaleOverlaysOfDeletedCluster(t *testing.T) {
	f := newFixture(t, []types.Cluster{cluster("c1", "prod-eu", nil)}, nil)
	ctx := context.Background()
	if err := f.svc.RerenderOrg(ctx, "org:1"); err != nil {
		t.Fatal(err)
	}
	// Cluster deleted: no longer in the registry; the event carries its name.
	f.clusters.list = nil
	if err := f.svc.RerenderOrg(ctx, "org:1", "prod-eu"); err != nil {
		t.Fatal(err)
	}
	files := f.git.Files("acme/acme-inari-state", "main")
	if files["clusters/prod-eu/dex/values.yaml"] != "" || files["clusters/prod-eu/argocd-config/values.yaml"] != "" {
		t.Errorf("deleted cluster overlays must be purged: %v", keysOf(files))
	}
	if !strings.Contains(files["dex/applicationset.yaml"], "elements: []") {
		t.Errorf("appset must drain to empty elements:\n%s", files["dex/applicationset.yaml"])
	}
}

func TestRerenderOrgSkipsArgocdConfigWithoutChartPin(t *testing.T) {
	f := newFixture(t, []types.Cluster{cluster("c1", "prod-eu", nil)}, nil)
	f.svc.cfg.PlatformChartVersion = ""
	if err := f.svc.RerenderOrg(context.Background(), "org:1"); err != nil {
		t.Fatal(err)
	}
	files := f.git.Files("acme/acme-inari-state", "main")
	if files["dex/applicationset.yaml"] == "" {
		t.Fatal("dex appset must still render")
	}
	for p := range files {
		if strings.HasPrefix(p, "argocd-config/") {
			t.Errorf("argocd-config must be skipped without a chart pin: %s", p)
		}
	}
	if len(f.queue.cmds) != 1 {
		t.Errorf("commands = %d, want 1 (dex only)", len(f.queue.cmds))
	}
}

func TestRerenderOrgPullRequestPolicyDefersDelivery(t *testing.T) {
	f := newFixture(t, []types.Cluster{cluster("c1", "prod-eu", nil)}, nil)
	f.repo.CommitPolicy = types.CommitPolicyPullRequest
	if err := f.svc.RerenderOrg(context.Background(), "org:1"); err != nil {
		t.Fatal(err)
	}
	if len(f.git.PRs) != 1 {
		t.Fatalf("PRs = %d, want 1", len(f.git.PRs))
	}
	if len(f.queue.cmds) != 0 {
		t.Errorf("delivery must wait for the PR merge: %v", f.queue.cmds)
	}
	// Simulate the merge: the PR files land on main.
	for _, file := range f.git.PRs[0].Files {
		if _, err := f.git.CommitFiles(context.Background(), f.repo.Repo, "main", []gitprovider.File{file}, "merge"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.svc.RerenderOrg(context.Background(), "org:1"); err != nil {
		t.Fatal(err)
	}
	if len(f.queue.cmds) != 2 {
		t.Errorf("after merge, delivery must proceed: %d commands", len(f.queue.cmds))
	}
}

func TestRerenderOrgMultiBaselineGrouping(t *testing.T) {
	f := newFixture(t, []types.Cluster{
		cluster("c1", "prod-eu", nil),
		cluster("c2", "prod-us", nil),
	}, nil)
	repo2 := &types.TenantGitRepo{
		ID: "repo-2", OrgID: "org:1", Name: "baseline-b", Repo: "acme/acme-state-b",
		Scope: types.GitRepoScopePlatform, CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main",
	}
	if _, err := f.git.EnsureRepo(context.Background(), repo2.Repo); err != nil {
		t.Fatal(err)
	}
	// Rebind c2 to repo2.
	f.svc.baselines = fakeBaselines{byCluster: map[string]string{"c1": "repo-1", "c2": "repo-2"}}
	f.svc.repos = fakeRepoLister{repos: []*types.TenantGitRepo{f.repo, repo2}}
	f.svc.git = gitprovider.NewRepoResolver(
		fakeRepoStore{byID: map[string]*types.TenantGitRepo{"repo-1": f.repo, "repo-2": repo2}, def: f.repo},
		nil, gitprovider.StaticResolver{P: f.git})

	if err := f.svc.RerenderOrg(context.Background(), "org:1"); err != nil {
		t.Fatal(err)
	}
	set1 := f.git.Files("acme/acme-inari-state", "main")["dex/applicationset.yaml"]
	set2 := f.git.Files("acme/acme-state-b", "main")["dex/applicationset.yaml"]
	if !strings.Contains(set1, "prod-eu") || strings.Contains(set1, "prod-us") {
		t.Errorf("repo1 appset must list only prod-eu:\n%s", set1)
	}
	if !strings.Contains(set2, "prod-us") || strings.Contains(set2, "prod-eu") {
		t.Errorf("repo2 appset must list only prod-us:\n%s", set2)
	}
	// Each cluster's delivery carries ITS repo's $values URL.
	for _, cmd := range f.queue.cmds {
		m := bridgeManifest(t, cmd)
		if cmd.ClusterID == "c1" && !strings.Contains(m, "acme-inari-state") {
			t.Errorf("c1 delivery must reference repo1:\n%s", m)
		}
		if cmd.ClusterID == "c2" && !strings.Contains(m, "acme-state-b") {
			t.Errorf("c2 delivery must reference repo2:\n%s", m)
		}
	}
}

// Regression (QA): a malformed Dex image override is a hard config error —
// silently dropping the dex spec would stall the delivery gate forever with
// the stale committed manifest left in place.
func TestRerenderOrgBadDexImageFails(t *testing.T) {
	f := newFixture(t, []types.Cluster{cluster("c1", "prod-eu", nil)}, nil)
	f.svc.cfg.DexImage = "ghcr.io/dexidp/dex@sha256:1a2b3c" // digest ref: rejected
	if err := f.svc.RerenderOrg(context.Background(), "org:1"); err == nil {
		t.Fatal("bad dex image must fail the render (loud config error)")
	}
}

// Regression (QA): the delivery gate covers BOTH appsets — a cluster's view
// must not go out while its repo still lacks the argocd-config appset (its
// $values overlays would render broken children).
func TestRerenderOrgDeliveryGateCoversBothAppSets(t *testing.T) {
	f := newFixture(t, []types.Cluster{cluster("c1", "prod-eu", nil)}, nil)
	ctx := context.Background()
	f.repo.CommitPolicy = types.CommitPolicyPullRequest
	if err := f.svc.RerenderOrg(ctx, "org:1"); err != nil {
		t.Fatal(err)
	}
	if len(f.git.PRs) != 1 || len(f.queue.cmds) != 0 {
		t.Fatalf("first pass: PRs=%d cmds=%d, want 1/0", len(f.git.PRs), len(f.queue.cmds))
	}
	// Merge ONLY the dex files (split-brain merge simulation): the dex
	// appset is live, argocd-config is not.
	for _, file := range f.git.PRs[0].Files {
		if !strings.HasPrefix(file.Path, "dex/") && !strings.HasPrefix(file.Path, "clusters/") {
			continue
		}
		if _, err := f.git.CommitFiles(ctx, f.repo.Repo, "main", []gitprovider.File{file}, "merge dex half"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.svc.RerenderOrg(ctx, "org:1"); err != nil {
		t.Fatal(err)
	}
	if len(f.queue.cmds) != 0 {
		t.Errorf("delivery must wait until BOTH appsets live: %d commands", len(f.queue.cmds))
	}
	// Merge the rest: delivery proceeds.
	for _, file := range f.git.PRs[0].Files {
		if _, err := f.git.CommitFiles(ctx, f.repo.Repo, "main", []gitprovider.File{file}, "merge rest"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.svc.RerenderOrg(ctx, "org:1"); err != nil {
		t.Fatal(err)
	}
	if len(f.queue.cmds) != 2 {
		t.Errorf("after full merge: %d commands, want 2", len(f.queue.cmds))
	}
}

// Regression (QA): an opted-out cluster that was never managed by the repo
// gets no drain delivery (an empty appset would be pointless noise).
func TestRerenderOrgNeverManagedOptOutGetsNoDrain(t *testing.T) {
	f := newFixture(t, []types.Cluster{
		cluster("c1", "prod-eu", map[string]string{DisabledLabel: DisabledLabelValue}),
	}, nil)
	if err := f.svc.RerenderOrg(context.Background(), "org:1"); err != nil {
		t.Fatal(err)
	}
	if files := f.git.Files("acme/acme-inari-state", "main"); len(files) != 0 {
		t.Errorf("never-managed opt-out must produce no renders: %v", keysOf(files))
	}
	if len(f.queue.cmds) != 0 {
		t.Errorf("never-managed opt-out must produce no deliveries: %v", f.queue.cmds)
	}
}

func TestRerenderOrgSkipsClustersWithoutBaseline(t *testing.T) {
	f := newFixture(t, []types.Cluster{cluster("c1", "prod-eu", nil)}, nil)
	f.svc.baselines = fakeBaselines{byCluster: map[string]string{}} // unbound
	if err := f.svc.RerenderOrg(context.Background(), "org:1"); err != nil {
		t.Fatal(err)
	}
	if files := f.git.Files("acme/acme-inari-state", "main"); len(files) != 0 {
		t.Errorf("unbound cluster must not produce renders: %v", keysOf(files))
	}
}

// --- helpers ---

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// bridgeManifest extracts the manifest field from a bridge command payload
// (protojson Any{structpb.Struct}), mirroring the addons test decode.
func bridgeManifest(t *testing.T, cmd types.AgentCommand) string {
	t.Helper()
	var cmdAny anypb.Any
	if err := protojson.Unmarshal(cmd.Payload, &cmdAny); err != nil {
		t.Fatalf("command payload: %v", err)
	}
	var doc structpb.Struct
	if err := cmdAny.UnmarshalTo(&doc); err != nil {
		t.Fatal(err)
	}
	out := doc.Fields["manifest"].GetStringValue()
	if out == "" {
		t.Fatalf("no manifest in payload:\n%s", cmd.Payload)
	}
	return out
}
