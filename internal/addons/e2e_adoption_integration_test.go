//go:build integration

// End-to-end adoption flow for first-class addons (Feature C, plan §6,
// risk item 2) over the real HTTP surface, real Postgres, fake git, and a
// capture queue standing in for the agent: scanner report → adopt with
// prune OFF + take-ownership → registration command → version/values
// update commit → health fold-back → explicit enable-prune with audit.
// The agent-side legs (scanner emission, manifest upsert, pre-existing
// resource survival) are covered by the inari-agent suites; the live
// kind+ArgoCD validation is the e2e-tagged layer.
package addons_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/7K-Inari/inari-server/internal/addons"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/types"
)

// discoveryEvent builds the exact wire payload the agent scanner emits
// (structpb bridge, EVENT_TYPE_REPORT_ADDONS) and runs it through the
// same decode the gateway session uses before calling the sink.
func reportDiscovery(t *testing.T, f *itFixture, clusterID string, items []map[string]any) {
	t.Helper()
	list := make([]any, 0, len(items))
	for _, it := range items {
		list = append(list, it)
	}
	doc, err := structpb.NewStruct(map[string]any{"addons": list})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := anypb.New(doc)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := addons.DecodeReportAddons(payload)
	if err != nil {
		t.Fatalf("bridge decode: %v", err)
	}
	if err := f.svc.IngestDiscovery(context.Background(), "org:1", clusterID, decoded); err != nil {
		t.Fatalf("ingest: %v", err)
	}
}

type addonListView struct {
	ID           string `json:"id"`
	ClusterID    string `json:"clusterId"`
	CatalogItem  string `json:"catalogItem"`
	State        string `json:"state"`
	DeployMode   string `json:"deployMode"`
	ArgoCDApp    string `json:"argocdApp"`
	ChartVersion string `json:"chartVersion"`
	Health       string `json:"health"`
	Sync         string `json:"sync"`
	PruneEnabled bool   `json:"pruneEnabled"`
	CommitSHA    string `json:"commitSha"`
}

func listAddons(t *testing.T, f *itFixture, clusterID string) []addonListView {
	t.Helper()
	code, body := f.req(t, "GET", "/api/v1/tenants/acme/clusters/"+clusterID+"/addons", "admin", "")
	if code != 200 {
		t.Fatalf("list addons: %d %s", code, body)
	}
	var out struct {
		Addons []addonListView `json:"addons"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out.Addons
}

func findAddon(views []addonListView, catalogItem string) *addonListView {
	for i, v := range views {
		if v.CatalogItem == catalogItem {
			return &views[i]
		}
	}
	return nil
}

func auditActions(t *testing.T, f *itFixture) []string {
	t.Helper()
	rows, err := f.database.Pool.Query(context.Background(),
		`SELECT action FROM audit_events WHERE org_id = 'org:1' ORDER BY created_at, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func TestAddonAdoptionEndToEnd(t *testing.T) {
	f := newITServer(t, types.CommitPolicyDirect)
	defer f.srv.Close()
	ctx := context.Background()

	// --- 1. Discovery: the agent scanner's bridge report lands as a
	// discovered row, visible on the cluster addons list.
	reportDiscovery(t, f, "cluster-1", []map[string]any{{
		"catalogItem": "platform:cert-manager", "releaseName": "cert-manager",
		"namespace": "cert-manager", "chart": "cert-manager", "repoUrl": "https://charts.jetstack.io",
	}})
	discovered := findAddon(listAddons(t, f, "cluster-1"), "platform:cert-manager")
	if discovered == nil || discovered.State != "discovered" {
		t.Fatalf("after discovery: %+v", discovered)
	}

	// --- 2. Adopt via the API: prune OFF + take-ownership, application mode.
	code, body := f.req(t, "POST",
		"/api/v1/tenants/acme/clusters/cluster-1/addons/platform:cert-manager/adopt", "admin",
		`{"version":"v1.16.2","values":{"replicaCount":2}}`)
	if code != 200 {
		t.Fatalf("adopt: %d %s", code, body)
	}
	var adoptOut struct {
		Addon     addonListView `json:"addon"`
		CommitSHA string        `json:"commitSha"`
	}
	if err := json.Unmarshal([]byte(body), &adoptOut); err != nil {
		t.Fatal(err)
	}
	addon := adoptOut.Addon
	if addon.State != "managed" || addon.CommitSHA == "" && adoptOut.CommitSHA == "" {
		t.Fatalf("adopt result: %+v", adoptOut)
	}
	if addon.PruneEnabled {
		t.Error("adoption must keep prune OFF (risk item 2)")
	}
	if !strings.HasPrefix(addon.ArgoCDApp, "inari-addon-") {
		t.Errorf("argocdApp = %q", addon.ArgoCDApp)
	}
	// The discovered row was adopted in place (same ID).
	if addon.ID != discovered.ID {
		t.Errorf("adopted row ID %q != discovered row ID %q", addon.ID, discovered.ID)
	}

	// The committed desired state carries prune OFF + take-ownership.
	app := f.git.Files("acme/acme-inari-state", "main")["addons/cert-manager/application.yaml"]
	if !strings.Contains(app, "prune: false") || !strings.Contains(app, "TakeOwnership=true") {
		t.Errorf("committed application:\n%s", app)
	}
	if !strings.Contains(app, "targetRevision: v1.16.2") {
		t.Error("chart version must pin the adopted version")
	}

	// The registration command is the manifest bridge (agent upserts the
	// committed application.yaml verbatim).
	if len(f.queue.cmds) != 1 {
		t.Fatalf("commands = %d", len(f.queue.cmds))
	}
	cmd := f.queue.cmds[0]
	if cmd.Type != addons.RegisterAppManifestEventType || cmd.ClusterID != "cluster-1" {
		t.Errorf("command = %+v", cmd)
	}
	var cmdAny anypb.Any
	if err := protojson.Unmarshal(cmd.Payload, &cmdAny); err != nil {
		t.Fatalf("command payload: %v", err)
	}
	var bridge structpb.Struct
	if err := cmdAny.UnmarshalTo(&bridge); err != nil {
		t.Fatal(err)
	}
	if bridge.Fields["manifest"].GetStringValue() != app {
		t.Error("bridge manifest must be the committed application.yaml verbatim")
	}
	if bridge.Fields["commandId"].GetStringValue() != addon.ArgoCDApp {
		t.Errorf("bridge commandId = %q", bridge.Fields["commandId"].GetStringValue())
	}

	// --- 3. PATCH version/values: the commit lands in the repo.
	code, body = f.req(t, "PATCH", "/api/v1/tenants/acme/addons/"+addon.ID, "admin",
		`{"chartVersion":"v1.16.1","values":{"replicaCount":3,"crds":{"enabled":true}}}`)
	if code != 200 {
		t.Fatalf("update: %d %s", code, body)
	}
	app = f.git.Files("acme/acme-inari-state", "main")["addons/cert-manager/application.yaml"]
	if !strings.Contains(app, "targetRevision: v1.16.1") {
		t.Error("update must re-pin the chart version")
	}
	vals := f.git.Files("acme/acme-inari-state", "main")["addons/cert-manager/values.yaml"]
	if !strings.Contains(vals, "replicaCount: 3") {
		t.Errorf("values.yaml = %q", vals)
	}

	// Invalid values are rejected 422 with field-level errors.
	code, body = f.req(t, "PATCH", "/api/v1/tenants/acme/addons/"+addon.ID, "admin",
		`{"values":{"replicaCount":0}}`)
	if code != 422 || !strings.Contains(body, "replicaCount") {
		t.Errorf("invalid values: want 422 with field errors, got %d %s", code, body)
	}

	// --- 4. Health folds back: the agent's status update for the
	// registered Application lands on the addon row.
	matched, err := f.inv.ApplyStatus(ctx, "org:1", "cluster-1", inventory.StatusUpdate{
		Resource: types.ResourceRef{Kind: "Application", Name: addon.ArgoCDApp, Namespace: "argocd"},
		Health:   "healthy", Sync: "synced",
	})
	if err != nil || !matched {
		t.Fatalf("apply status: matched=%v err=%v", matched, err)
	}
	managed := findAddon(listAddons(t, f, "cluster-1"), "platform:cert-manager")
	if managed.Health != "healthy" || managed.Sync != "synced" {
		t.Errorf("health fold-back = %q/%q", managed.Health, managed.Sync)
	}

	// --- 5. enable-prune flips only on the explicit action; audited.
	code, body = f.req(t, "POST", "/api/v1/tenants/acme/addons/"+addon.ID+"/enable-prune", "admin", "")
	if code != 200 {
		t.Fatalf("enable-prune: %d %s", code, body)
	}
	app = f.git.Files("acme/acme-inari-state", "main")["addons/cert-manager/application.yaml"]
	if !strings.Contains(app, "prune: true") {
		t.Error("enable-prune must re-render with prune on")
	}
	code, _ = f.req(t, "POST", "/api/v1/tenants/acme/addons/"+addon.ID+"/enable-prune", "admin", "")
	if code != 409 {
		t.Errorf("second enable-prune: want 409, got %d", code)
	}

	// --- Audit trail covers the whole lifecycle.
	actions := auditActions(t, f)
	for _, want := range []string{"addon.discovered", "addon.adopted", "addon.updated", "addon.prune_enabled"} {
		found := false
		for _, a := range actions {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("audit action %q missing; have %v", want, actions)
		}
	}
}

// ApplicationSet mode (plan §6, decision 8): a fleet adoption over a
// 2-cluster selector renders a list-generator ApplicationSet whose
// per-cluster child Applications fold health back per cluster.
func TestAddonAdoptionApplicationSetEndToEnd(t *testing.T) {
	f := newITServer(t, types.CommitPolicyDirect)
	defer f.srv.Close()
	ctx := context.Background()

	// Discovered on both prod clusters.
	for _, c := range []string{"cluster-1", "cluster-2"} {
		reportDiscovery(t, f, c, []map[string]any{{
			"catalogItem": "platform:cert-manager", "releaseName": "cert-manager", "namespace": "cert-manager",
		}})
	}

	code, body := f.req(t, "POST",
		"/api/v1/tenants/acme/clusters/cluster-1/addons/platform:cert-manager/adopt", "admin",
		`{"version":"v1.16.2","deployMode":"applicationset","clusterSelector":{"env":"prod"}}`)
	if code != 200 {
		t.Fatalf("fleet adopt: %d %s", code, body)
	}
	var out struct {
		Addon addonListView `json:"addon"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	fleet := out.Addon
	if fleet.ClusterID != "*" || fleet.DeployMode != "applicationset" {
		t.Fatalf("fleet row: %+v", fleet)
	}
	if !strings.HasPrefix(fleet.ArgoCDApp, "inari-addonset-") {
		t.Errorf("argocdApp = %q", fleet.ArgoCDApp)
	}

	// The rendered ApplicationSet fans out to exactly the selector-matched
	// clusters via the list generator (per-cluster Applications in ArgoCD).
	appset := f.git.Files("acme/acme-inari-state", "main")["addons/cert-manager/applicationset.yaml"]
	if !strings.Contains(appset, "cluster: prod-eu") || !strings.Contains(appset, "cluster: prod-us") {
		t.Errorf("list generator must contain both prod clusters:\n%s", appset)
	}
	if strings.Contains(appset, "TakeOwnership=true") == false {
		t.Error("fleet adoption must carry take-ownership")
	}
	// Per-cluster discovered rows were absorbed into the fleet row.
	for _, c := range []string{"cluster-1", "cluster-2"} {
		if v := findAddon(listAddons(t, f, c), "platform:cert-manager"); v == nil || v.State != "managed" {
			t.Errorf("%s: addon view = %+v", c, v)
		}
	}

	// The appset registration bridge command anchors on the adopting cluster.
	if len(f.queue.cmds) != 1 || f.queue.cmds[0].Type != addons.RegisterAppSetEventType {
		t.Fatalf("commands = %+v", f.queue.cmds)
	}

	// A per-cluster child Application (inari-addon-<id>-<cluster>) folds
	// health into the fleet row.
	childApp := "inari-addon-" + strings.TrimPrefix(fleet.ArgoCDApp, "inari-addonset-") + "-prod-eu"
	matched, err := f.inv.ApplyStatus(ctx, "org:1", "cluster-1", inventory.StatusUpdate{
		Resource: types.ResourceRef{Kind: "Application", Name: childApp, Namespace: "argocd"},
		Health:   "healthy", Sync: "synced",
	})
	if err != nil || !matched {
		t.Fatalf("child app status: matched=%v err=%v", matched, err)
	}
	v := findAddon(listAddons(t, f, "cluster-1"), "platform:cert-manager")
	if v.Health != "healthy" {
		t.Errorf("fleet health after child fold = %q", v.Health)
	}
}
