package renderer

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

// Golden-file tests for rendered YAML. Regenerate with:
//
//	go test ./internal/renderer/ -run TestGolden -update
var update = flag.Bool("update", false, "regenerate golden files")

type goldenCase struct {
	name    string
	desc    types.SourceDescriptor
	params  RenderParams
	resolve ResolveRGDFunc
}

func goldenCases() []goldenCase {
	helmApp := goldenCase{
		name: "helm-app",
		desc: helmDesc(),
		params: RenderParams{
			Name: "cert-manager", Namespace: "cert-manager", ID: "addon-01",
			AppPrefix: PrefixAddon, DeployMode: types.AddonDeployModeApplication,
			Clusters:    []ClusterTarget{{ID: "c1", Name: "prod-eu"}},
			Values:      json.RawMessage(`{"crds":{"enabled":true}}`),
			SyncOptions: []string{"TakeOwnership=true"},
			RepoURL:     "https://github.com/acme/acme-inari-state",
			BaseBranch:  "main", Path: "addons/cert-manager",
		},
	}
	helmAppset := helmApp
	helmAppset.name = "helm-appset"
	helmAppset.params.DeployMode = types.AddonDeployModeApplicationSet
	helmAppset.params.Clusters = []ClusterTarget{{ID: "c1", Name: "prod-eu"}, {ID: "c2", Name: "prod-us"}}

	helmAppsetFields := helmAppset
	helmAppsetFields.name = "helm-appset-fields"
	helmAppsetFields.params.AppNameTemplate = "{{dexAppName}}"
	helmAppsetFields.params.CascadeDelete = true
	helmAppsetFields.params.Clusters = []ClusterTarget{
		{ID: "c1", Name: "prod-eu", Fields: map[string]string{"dexAppName": "dex-c1", "clusterID": "c1"}},
		{ID: "c2", Name: "prod-us", Fields: map[string]string{"dexAppName": "dex-c2", "clusterID": "c2"}},
	}

	kroApp := goldenCase{
		name:    "kro-app",
		desc:    kroDesc(),
		resolve: staticRGD(testRGD),
		params: RenderParams{
			Name: "my-db", Namespace: "apps", ID: "my-db",
			AppPrefix: PrefixInstance, DeployMode: types.AddonDeployModeApplication,
			Clusters: []ClusterTarget{{ID: "c1", Name: "c1"}}, Prune: true,
			RepoURL:    "https://github.com/acme/acme-inari-state",
			BaseBranch: "main", Path: "clusters/c1/postgres-aws/my-db",
		},
	}
	kroAppset := kroApp
	kroAppset.name = "kro-appset"
	kroAppset.params.DeployMode = types.AddonDeployModeApplicationSet
	kroAppset.params.AppPrefix = PrefixAddon
	kroAppset.params.Clusters = []ClusterTarget{{ID: "c1", Name: "eu"}, {ID: "c2", Name: "us"}}

	manifestsMulti := goldenCase{
		name: "manifests-inline",
		desc: manifestsDesc(mustJSONString(`apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  key: value
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
`), nil),
		params: RenderParams{
			Name: "bundle", Namespace: "apps", ID: "bundle-1",
			AppPrefix: PrefixInstance, DeployMode: types.AddonDeployModeApplication,
			Clusters:   []ClusterTarget{{ID: "c1", Name: "c1"}},
			RepoURL:    "https://github.com/acme/acme-inari-state",
			BaseBranch: "main", Path: "clusters/c1/bundle/bundle-1",
		},
	}
	manifestsParams := manifestsMulti
	manifestsParams.name = "manifests-params"
	manifestsParams.desc = manifestsDesc(
		mustJSONString("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: ${policyName}\n"),
		map[string]string{"policyName": "deny-all"})

	return []goldenCase{helmApp, helmAppset, helmAppsetFields, kroApp, kroAppset, manifestsMulti, manifestsParams}
}

func TestGolden(t *testing.T) {
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			r := New(tc.resolve)
			files, err := r.Render(context.Background(), tc.desc, tc.params)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join("testdata", tc.name)
			// Rendered paths are repo-relative (e.g. addons/x/application.yaml);
			// golden files mirror that layout under testdata/<case>/.
			wantPaths := map[string]bool{}
			for _, f := range files {
				golden := filepath.Join(dir, filepath.FromSlash(f.Path))
				wantPaths[golden] = true
				if *update {
					if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(golden, f.Content, 0o644); err != nil {
						t.Fatal(err)
					}
					continue
				}
				want, err := os.ReadFile(golden)
				if err != nil {
					t.Fatalf("read golden %s: %v (regenerate with -update)", golden, err)
				}
				if string(want) != string(f.Content) {
					t.Errorf("%s diverges from golden %s:\n--- got ---\n%s\n--- want ---\n%s",
						f.Path, golden, f.Content, want)
				}
			}
			if !*update {
				// Stale goldens (files the renderer no longer emits) fail the test.
				err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if !d.IsDir() && !wantPaths[path] {
						t.Errorf("stale golden file %s (regenerate with -update)", path)
					}
					return nil
				})
				if err != nil {
					t.Fatalf("walk golden dir: %v (regenerate with -update)", err)
				}
			}
		})
	}
}
