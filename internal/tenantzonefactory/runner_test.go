package tenantzonefactory

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/platformresources"
	"github.com/7K-Inari/inari-server/internal/types"
)

func TestPreflightRules(t *testing.T) {
	base := PreflightInput{
		Slug: "acme-dev", Region: "eu-west-1", Tier: "starter", OUID: "ou-1",
		AccountQuota: 5, AllowedRegions: []string{"eu-west-1"}, AllowedTiers: []string{"starter"},
		RequiredTags: []string{"cost-center"}, Tags: map[string]string{"cost-center": "cc-1"},
	}
	if reasons := Preflight(base); len(reasons) != 0 {
		t.Errorf("valid request denied: %v", reasons)
	}

	bad := base
	bad.Slug = "ACME!"
	if reasons := Preflight(bad); len(reasons) == 0 {
		t.Error("invalid slug must be denied")
	}
	bad = base
	bad.ExistingSlugs = []string{"acme-dev"}
	if reasons := Preflight(bad); len(reasons) == 0 {
		t.Error("duplicate slug must be denied")
	}
	bad = base
	bad.AccountCount = 5
	if reasons := Preflight(bad); len(reasons) == 0 || !strings.Contains(reasons[0], "quota") {
		t.Errorf("exhausted quota must be denied with reason, got %v", reasons)
	}
	bad = base
	bad.Region = "us-east-1"
	if reasons := Preflight(bad); len(reasons) == 0 {
		t.Error("region outside allow-list must be denied")
	}
	bad = base
	bad.Tags = nil
	if reasons := Preflight(bad); len(reasons) == 0 || !strings.Contains(reasons[0], "cost-center") {
		t.Errorf("missing mandatory tag must be denied with reason, got %v", reasons)
	}
}

type fakeWiring struct {
	wired   *types.TenantZone
	unwired *types.TenantZone
	err     error
}

func (f *fakeWiring) WireZone(_ context.Context, z *types.TenantZone, _ string) (*WiringResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.wired = z
	return &WiringResult{OrgID: "org:z1", KeycloakOrgID: "kc-z1", ClusterID: "cluster:1", CloudAccountID: "ca:1", GitRepo: z.Slug + "-inari-state"}, nil
}
func (f *fakeWiring) UnwireZone(_ context.Context, z *types.TenantZone) error {
	f.unwired = z
	return f.err
}

type fakeClusters struct {
	cordoned        string
	decommissioned  string
	drained         []string
	cordonErr       error
	decommissionErr error
}

func (f *fakeClusters) Cordon(_ context.Context, _, clusterID string) error {
	f.cordoned = clusterID
	return f.cordonErr
}
func (f *fakeClusters) Decommission(_ context.Context, _, clusterID string, _ bool) ([]string, error) {
	f.decommissioned = clusterID
	f.drained = []string{"i1"}
	return f.drained, f.decommissionErr
}

func testEnv() (*Env, *FakeOrganizations, *FakeTrustBootstrap, *FakeProvisioner, *fakeWiring, *fakeClusters) {
	aws := NewFakeOrganizations()
	boot := NewFakeTrustBootstrap()
	prov := NewFakeProvisioner()
	w := &fakeWiring{}
	cl := &fakeClusters{}
	return &Env{
		AWS: aws, Bootstrap: boot, Prov: prov, Wiring: w, Clusters: cl,
		Config: Config{AllowedRegions: []string{"eu-west-1"}, AllowedTiers: []string{"starter"}, AccountQuota: 10},
	}, aws, boot, prov, w, cl
}

func testZone() *types.TenantZone {
	return &types.TenantZone{
		ID: "zone:1", Slug: "acme-dev", Region: "eu-west-1", Tier: "starter", OUID: "ou-1",
		State: types.ZoneStateProvisioning,
	}
}

func collectUpdates() (OnUpdate, *[]string) {
	var seq []string
	return func(_ context.Context, rc *RunContext, st *types.TenantZoneStep) error {
		seq = append(seq, st.Step+":"+st.Status)
		return nil
	}, &seq
}

func TestProvisionHappyPath(t *testing.T) {
	env, aws, boot, prov, _, _ := testEnv()
	env.AWS = aws
	zone := testZone()
	rc := &RunContext{Zone: zone, Steps: map[string]*types.TenantZoneStep{}, Actor: "user-1"}
	onUpdate, seq := collectUpdates()

	// Async steps wait on first pass (CreateAccount + MR start), so run to
	// completion across multiple runner invocations like the poll loop does.
	var complete bool
	var err error
	for i := 0; i < 8 && !complete; i++ {
		complete, err = RunSteps(context.Background(), env, ProvisionOrder, provisionSteps, rc, onUpdate)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if !complete {
		t.Fatalf("provision did not complete; steps = %v", *seq)
	}
	if zone.AWSAccountID == "" {
		t.Error("aws account id not recorded")
	}
	if zone.OrgID != "org:z1" || zone.ClusterID != "cluster:1" || zone.GitRepo != "acme-dev-inari-state" {
		t.Errorf("wiring result not applied: %+v", zone)
	}
	if len(aws.CreatedAccounts()) != 1 {
		t.Errorf("created accounts = %v, want 1", aws.CreatedAccounts())
	}
	if boot.Roles[zone.AWSAccountID] == "" {
		t.Error("OIDC role not bootstrapped")
	}
	if rc.Steps[types.ZoneStepEKSProvision].ExternalRef == "" {
		t.Error("eks MR ref not recorded")
	}
	_ = prov
}

func TestProvisionResumeAfterRestart(t *testing.T) {
	env, aws, _, _, _, _ := testEnv()
	aws.SucceedAfterPolls = 3
	zone := testZone()
	rc := &RunContext{Zone: zone, Steps: map[string]*types.TenantZoneStep{}, Actor: "user-1"}
	onUpdate, _ := collectUpdates()

	// First process: starts the vend, waits, "crashes" after one poll.
	if _, err := RunSteps(context.Background(), env, ProvisionOrder, provisionSteps, rc, onUpdate); err != nil {
		t.Fatal(err)
	}
	ref := rc.Steps[types.ZoneStepAccountVend].ExternalRef
	if ref == "" {
		t.Fatal("vend request id not persisted")
	}
	// "Restart": new runner over the persisted zone+steps; must NOT issue a
	// second CreateAccount.
	var complete bool
	for i := 0; i < 10 && !complete; i++ {
		var err error
		complete, err = RunSteps(context.Background(), env, ProvisionOrder, provisionSteps, rc, onUpdate)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(aws.CreatedAccounts()) != 1 {
		t.Errorf("resume re-created the account: %v", aws.CreatedAccounts())
	}
	if !complete {
		t.Error("resume did not complete")
	}
}

func TestProvisionPreflightDeniedIsPermanent(t *testing.T) {
	env, _, _, _, _, _ := testEnv()
	zone := testZone()
	zone.Region = "ap-southeast-2" // outside allow-list
	rc := &RunContext{Zone: zone, Steps: map[string]*types.TenantZoneStep{}, Actor: "user-1"}
	onUpdate, _ := collectUpdates()

	_, err := RunSteps(context.Background(), env, ProvisionOrder, provisionSteps, rc, onUpdate)
	if !errors.Is(err, ErrPreflightDenied) {
		t.Fatalf("err = %v, want ErrPreflightDenied", err)
	}
	if rc.Steps[types.ZoneStepPreflight].Status != types.ZoneStepFailed {
		t.Errorf("preflight step = %q, want failed", rc.Steps[types.ZoneStepPreflight].Status)
	}
	if rc.Steps[types.ZoneStepAccountVend] != nil {
		t.Error("no later step may start after preflight denial")
	}
}

func TestProvisionStepFailureStopsChain(t *testing.T) {
	env, aws, _, _, _, _ := testEnv()
	aws.FailCreate = true
	zone := testZone()
	rc := &RunContext{Zone: zone, Steps: map[string]*types.TenantZoneStep{}, Actor: "user-1"}
	onUpdate, _ := collectUpdates()

	var err error
	for i := 0; i < 5; i++ {
		_, err = RunSteps(context.Background(), env, ProvisionOrder, provisionSteps, rc, onUpdate)
		if err != nil {
			break
		}
	}
	if err == nil || !strings.Contains(err.Error(), "account vend failed") {
		t.Fatalf("err = %v, want vend failure", err)
	}
	if rc.Steps[types.ZoneStepTrustBootstrap] != nil && rc.Steps[types.ZoneStepTrustBootstrap].Status == types.ZoneStepSucceeded {
		t.Error("trust bootstrap must not run after vend failure")
	}
}

func TestDecommissionReverses(t *testing.T) {
	env, _, _, prov, w, cl := testEnv()
	zone := testZone()
	zone.State = types.ZoneStateDecommissioning
	zone.AWSAccountID = "100000000001"
	zone.ClusterID = "cluster:1"
	rc := &RunContext{Zone: zone, Steps: map[string]*types.TenantZoneStep{
		types.ZoneStepEKSProvision: {ZoneID: zone.ID, Step: types.ZoneStepEKSProvision, Status: types.ZoneStepSucceeded, ExternalRef: ""},
	}, Actor: "user-1"}
	// Seed an EKS MR as if provisioning had run.
	ref, err := prov.ApplyEKSMR(context.Background(), zone.AWSAccountID, zone.Region, zone.Tier)
	if err != nil {
		t.Fatal(err)
	}
	rc.Steps[types.ZoneStepEKSProvision].ExternalRef = ref

	onUpdate, _ := collectUpdates()
	var complete bool
	for i := 0; i < 8 && !complete; i++ {
		complete, err = RunSteps(context.Background(), env, DecommissionOrder, decommissionSteps, rc, onUpdate)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if !complete {
		t.Fatal("decommission did not complete")
	}
	if cl.cordoned != "cluster:1" || cl.decommissioned != "cluster:1" {
		t.Errorf("cluster lifecycle not driven: cordoned=%q decommissioned=%q", cl.cordoned, cl.decommissioned)
	}
	if gone, _ := prov.MRDeleted(context.Background(), ref); !gone {
		t.Error("EKS MR not deleted")
	}
	if w.unwired != zone {
		t.Error("identities not revoked")
	}
	if rc.Steps[types.ZoneStepAccountClose].Status != types.ZoneStepSucceeded {
		t.Errorf("account close = %q", rc.Steps[types.ZoneStepAccountClose].Status)
	}
}

// manifestDeletingWiring records platform-manifest deletions.
type manifestDeletingWiring struct {
	fakeWiring
	deleted []string
}

func (m *manifestDeletingWiring) DeleteTenantManifests(_ context.Context, orgSlug string) error {
	m.deleted = append(m.deleted, orgSlug)
	return nil
}

func TestDecommissionDeletesPlatformManifests(t *testing.T) {
	env, _, _, _, _, _ := testEnv()
	w := &manifestDeletingWiring{}
	env.Wiring = w
	zone := testZone()
	zone.State = types.ZoneStateDecommissioning
	rc := &RunContext{Zone: zone, Steps: map[string]*types.TenantZoneStep{}, Actor: "user-1"}
	onUpdate, _ := collectUpdates()

	var complete bool
	var err error
	for i := 0; i < 8 && !complete; i++ {
		complete, err = RunSteps(context.Background(), env, DecommissionOrder, decommissionSteps, rc, onUpdate)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if !complete {
		t.Fatal("decommission did not complete")
	}
	if len(w.deleted) != 1 || w.deleted[0] != zone.Slug {
		t.Errorf("deleted manifests = %v, want [%s]", w.deleted, zone.Slug)
	}
	step := rc.Steps[types.ZoneStepPlatformManifestsDelete]
	if step == nil || step.Status != types.ZoneStepSucceeded {
		t.Errorf("platform_manifests_delete step = %+v, want succeeded", step)
	}
}

func TestDecommissionSkipsManifestDeleteWithoutSeam(t *testing.T) {
	env, _, _, _, _, _ := testEnv() // fakeWiring has no DeleteTenantManifests
	zone := testZone()
	zone.State = types.ZoneStateDecommissioning
	rc := &RunContext{Zone: zone, Steps: map[string]*types.TenantZoneStep{}, Actor: "user-1"}
	onUpdate, _ := collectUpdates()

	var complete bool
	var err error
	for i := 0; i < 8 && !complete; i++ {
		complete, err = RunSteps(context.Background(), env, DecommissionOrder, decommissionSteps, rc, onUpdate)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if !complete {
		t.Fatal("decommission did not complete")
	}
	step := rc.Steps[types.ZoneStepPlatformManifestsDelete]
	if step == nil || step.Status != types.ZoneStepSucceeded {
		t.Errorf("platform_manifests_delete step = %+v, want succeeded (no-op without the seam)", step)
	}
}

func TestModuleWiringDeleteTenantManifests(t *testing.T) {
	ctx := context.Background()
	git := gitprovider.NewFake()
	w := &ModuleWiring{Git: git, PlatformGitOpsRepo: "org/platform-gitops"}
	org := &types.Organization{ID: "org:1", Slug: "acme-dev"}

	// Seed the repo the way WireZone does.
	if _, err := git.EnsureRepo(ctx, "org/platform-gitops"); err != nil {
		t.Fatal(err)
	}
	if _, err := git.CommitFiles(ctx, "org/platform-gitops", "main",
		platformresources.RenderTenantManifests(org), "seed"); err != nil {
		t.Fatal(err)
	}

	if err := w.DeleteTenantManifests(ctx, org.Slug); err != nil {
		t.Fatal(err)
	}
	if got := git.Files("org/platform-gitops", "main"); len(got) != 0 {
		t.Errorf("remaining files = %+v, want none", got)
	}
	// Idempotent: a repeat delete is a no-op success.
	if err := w.DeleteTenantManifests(ctx, org.Slug); err != nil {
		t.Fatalf("repeat delete: %v", err)
	}

	// No platform repo configured: no-op.
	bare := &ModuleWiring{}
	if err := bare.DeleteTenantManifests(ctx, org.Slug); err != nil {
		t.Errorf("unconfigured wiring: %v", err)
	}
}

func TestDecommissionOwnershipBlockStopsChain(t *testing.T) {	env, _, _, _, _, cl := testEnv()
	cl.decommissionErr = errors.New("shared resources present")
	zone := testZone()
	zone.State = types.ZoneStateDecommissioning
	zone.ClusterID = "cluster:1"
	rc := &RunContext{Zone: zone, Steps: map[string]*types.TenantZoneStep{}, Actor: "user-1"}
	onUpdate, _ := collectUpdates()

	_, err := RunSteps(context.Background(), env, DecommissionOrder, decommissionSteps, rc, onUpdate)
	if err == nil || !strings.Contains(err.Error(), "drain") {
		t.Fatalf("err = %v, want drain failure", err)
	}
	if rc.Steps[types.ZoneStepEKSDelete] != nil {
		t.Error("eks delete must not start while drain is blocked")
	}
}
