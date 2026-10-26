package scaffold

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

// TestSeedGitopsRepoTemplateLoads verifies that the built-in gitops-repo
// template package is discoverable and valid through the FilePuller.
func TestSeedGitopsRepoTemplateLoads(t *testing.T) {
	env := &ExecEnv{Templates: &FilePuller{Root: "../../templates"}}
	pkgs, err := env.Templates.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range pkgs {
		if p.Manifest.Name == "gitops-repo" {
			found = true
			if p.Manifest.DisplayName == "" {
				t.Error("gitops-repo displayName is empty")
			}
			if p.Manifest.Description == "" {
				t.Error("gitops-repo description is empty")
			}
			if len(p.Manifest.Tags) == 0 {
				t.Error("gitops-repo tags are empty")
			}
			if p.Manifest.Version == "" {
				t.Error("gitops-repo version is empty")
			}
			if len(p.Schema) == 0 {
				t.Error("gitops-repo schema is empty")
			}
			if len(p.UIHints) == 0 {
				t.Error("gitops-repo uiSchema is empty")
			}
			if p.SkeletonDigest == "" {
				t.Error("gitops-repo skeleton digest is empty")
			}
		}
	}
	if !found {
		t.Fatal("gitops-repo template not found in templates/ dir")
	}
}

// TestSeedGitopsRepoRendersWithSchemaValidValues renders the shipped
// gitops-repo skeleton with schema-valid wizard values and asserts the
// output is complete and free of unrendered template syntax.
func TestSeedGitopsRepoRendersWithSchemaValidValues(t *testing.T) {
	env := &ExecEnv{Templates: &FilePuller{Root: "../../templates"}}
	run := &types.ScaffoldRun{
		ID: "run:1", OrgID: "org:acme", TemplateItemID: "template:gitops-repo",
		TemplateVersion: "0.1.0", DisplayName: "team-a-gitops",
		Values: json.RawMessage(`{"repoName":"team-a-gitops","team":"team-a","gitOrg":"my-org","commitPolicy":"direct","baseBranch":"main"}`),
	}
	rc := &RunContext{Run: run, Steps: map[string]*types.ScaffoldRunStep{},
		Tenant: &TenantContext{Slug: "acme", OrgID: "org:acme", Namespace: "acme", GroupPath: "tenant-acme/members"}}
	step := &types.ScaffoldRunStep{RunID: run.ID, Name: "rendering", State: types.ScaffoldStepRunning}
	done, err := stepRendering(context.Background(), env, rc, step)
	if err != nil || !done {
		t.Fatalf("gitops-repo template must render: done=%v err=%v", done, err)
	}
	var res renderResult
	if err := json.Unmarshal(step.Result, &res); err != nil || len(res.Files) == 0 {
		t.Fatalf("render result = %s (%v)", step.Result, err)
	}

	wantPaths := map[string]bool{
		"README.md":              false,
		"root-application.yaml":  false,
		"project.yaml":           false,
		"apps/README.md":         false,
		"clusters/README.md":     false,
		"policies/README.md":     false,
	}
	for _, f := range res.Files {
		if strings.Contains(f.Content, "{{") {
			t.Fatalf("%s: unrendered template syntax left: %s", f.Path, f.Content)
		}
		if _, ok := wantPaths[f.Path]; ok {
			wantPaths[f.Path] = true
		} else {
			t.Fatalf("unexpected rendered file: %s", f.Path)
		}
	}
	for path, seen := range wantPaths {
		if !seen {
			t.Fatalf("expected rendered file missing: %s", path)
		}
	}

	// Assert .tmpl suffix stripping happened.
	for _, f := range res.Files {
		if strings.HasSuffix(f.Path, ".tmpl") {
			t.Fatalf(".tmpl suffix not stripped: %s", f.Path)
		}
	}
}

// TestSeedGitopsRepoRendersWithEmptyValues verifies that the renderer
// fails fast when required wizard values are missing (strict missingkey=error).
func TestSeedGitopsRepoRendersWithEmptyValues(t *testing.T) {
	env := &ExecEnv{Templates: &FilePuller{Root: "../../templates"}}
	run := &types.ScaffoldRun{
		ID: "run:1", OrgID: "org:acme", TemplateItemID: "template:gitops-repo",
		TemplateVersion: "0.1.0", DisplayName: "test",
		Values: json.RawMessage(`{}`),
	}
	rc := &RunContext{Run: run, Steps: map[string]*types.ScaffoldRunStep{},
		Tenant: &TenantContext{Slug: "acme", OrgID: "org:acme", Namespace: "acme", GroupPath: "tenant-acme/members"}}
	step := &types.ScaffoldRunStep{RunID: run.ID, Name: "rendering", State: types.ScaffoldStepRunning}
	done, err := stepRendering(context.Background(), env, rc, step)
	if err == nil {
		t.Fatalf("expected error with empty values, got done=%v", done)
	}
	if !strings.Contains(err.Error(), "map has no entry for key") {
		t.Fatalf("expected missingkey error, got: %v", err)
	}
}

// TestSeedGitopsRepoRendersWithInvalidJSON verifies that malformed JSON
// values produce a decode error.
func TestSeedGitopsRepoRendersWithInvalidJSON(t *testing.T) {
	env := &ExecEnv{Templates: &FilePuller{Root: "../../templates"}}
	run := &types.ScaffoldRun{
		ID: "run:1", OrgID: "org:acme", TemplateItemID: "template:gitops-repo",
		TemplateVersion: "0.1.0", DisplayName: "test",
		Values: json.RawMessage(`{"repoName": invalid json`),
	}
	rc := &RunContext{Run: run, Steps: map[string]*types.ScaffoldRunStep{},
		Tenant: &TenantContext{Slug: "acme", OrgID: "org:acme", Namespace: "acme", GroupPath: "tenant-acme/members"}}
	step := &types.ScaffoldRunStep{RunID: run.ID, Name: "rendering", State: types.ScaffoldStepRunning}
	done, err := stepRendering(context.Background(), env, rc, step)
	if err == nil {
		t.Fatalf("expected error with invalid JSON, got done=%v", done)
	}
	if !strings.Contains(err.Error(), "decode run values") {
		t.Fatalf("expected decode error, got: %v", err)
	}
}

// TestSeedGitopsRepoTemplateSyncPlan verifies the template maps cleanly
// into a catalog item/version pair.
func TestSeedGitopsRepoTemplateSyncPlan(t *testing.T) {
	env := &ExecEnv{Templates: &FilePuller{Root: "../../templates"}}
	pkgs, err := env.Templates.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	items, versions, err := templateSyncPlan(pkgs)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for i, item := range items {
		if item.ID == "template:gitops-repo" {
			found = true
			if item.Source != types.CatalogSourceTemplate {
				t.Errorf("source = %q, want template", item.Source)
			}
			if versions[i].ItemID != item.ID {
				t.Errorf("version itemID = %q, want %q", versions[i].ItemID, item.ID)
			}
			if len(versions[i].Schema) == 0 {
				t.Error("version schema is empty")
			}
		}
	}
	if !found {
		t.Fatal("template:gitops-repo not found in sync plan")
	}
}
