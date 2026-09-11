// The git + pipeline phase steps (M8.W4, plan §5.2 steps 2-3):
// creating-repo turns the rendering step's rendered tree into the
// component's git repository; creating-pipeline registers the component's
// ArgoCD Application through the agent pull model (the CI file itself is
// part of the skeleton commit). Both steps are idempotent: a persisted
// step result short-circuits re-entry (crash between git write and step
// persist simply retries the external call; git writes are safe to redo).
package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// createRepoResult is the shape persisted in scaffold_run_steps.result for
// the creating-repo step; creating-pipeline consumes it for the
// Application source.
type createRepoResult struct {
	RepoName  string `json:"repoName"`
	RepoURL   string `json:"repoUrl"`
	Branch    string `json:"branch"`
	CommitSHA string `json:"commitSha"`
}

// createPipelineResult is the shape persisted for the creating-pipeline
// step. The rendered Application manifest is kept for debugging/audit.
type createPipelineResult struct {
	ApplicationName string `json:"applicationName"`
	PipelineURL     string `json:"pipelineUrl"`
	ClusterID       string `json:"clusterId"`
	Application     string `json:"application"`
}

// componentSlug allows letters, digits and dashes (k8s/DNS-safe repo and
// app names).
var componentSlug = regexp.MustCompile(`[^a-z0-9-]+`)

// componentName derives the component slug from the wizard values
// (name/serviceName) falling back to the run display name.
func componentName(rc *RunContext) (string, error) {
	name := ""
	var values map[string]any
	if len(rc.Run.Values) > 0 {
		_ = json.Unmarshal(rc.Run.Values, &values)
	}
	for _, key := range []string{"name", "serviceName"} {
		if v, ok := values[key].(string); ok && v != "" {
			name = v
			break
		}
	}
	if name == "" {
		name = rc.Run.DisplayName
	}
	slug := componentSlug.ReplaceAllString(strings.ToLower(name), "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		return "", fmt.Errorf("scaffold: cannot derive a component name from values/display name %q", name)
	}
	return slug, nil
}

// templatePackage re-reads the run's template package from the file source
// (same defensive pattern as stepRendering: name must be a single safe
// path segment and the on-disk version must match the run).
func templatePackage(env *ExecEnv, rc *RunContext) (*TemplatePackage, error) {
	if env == nil || env.Templates == nil {
		return nil, errors.New("scaffold: no template source configured")
	}
	name := strings.TrimPrefix(rc.Run.TemplateItemID, "template:")
	if name == "" || name != filepath.Base(name) {
		return nil, fmt.Errorf("scaffold: invalid template name %q", name)
	}
	pkg, err := readTemplateDir(filepath.Join(env.Templates.Root, name), name)
	if err != nil {
		return nil, err
	}
	if pkg.Manifest.Version != rc.Run.TemplateVersion {
		return nil, fmt.Errorf("scaffold: template %s version %s not found on disk (have %s)",
			name, rc.Run.TemplateVersion, pkg.Manifest.Version)
	}
	return pkg, nil
}

// manifestParam reads one string param from a manifest scaffold block
// (scaffold.<phase>.<key>), falling back to def when absent.
func manifestParam(m *TemplateManifest, phase, key, def string) string {
	if m.Scaffold == nil {
		return def
	}
	if v, ok := m.Scaffold[phase][key].(string); ok && v != "" {
		return v
	}
	return def
}

// mergeOutputs sets one key in the run's outputs object (the Service
// persists run.Outputs with the step transition).
func mergeOutputs(rc *RunContext, key string, value any) error {
	var outputs map[string]any
	if len(rc.Run.Outputs) > 0 {
		_ = json.Unmarshal(rc.Run.Outputs, &outputs)
	}
	if outputs == nil {
		outputs = map[string]any{}
	}
	outputs[key] = value
	raw, err := json.Marshal(outputs)
	if err != nil {
		return err
	}
	rc.Run.Outputs = raw
	return nil
}

// stepCreatingRepo creates the component repository under the platform git
// org (<GitOrg>/<tenant-slug>-<component>, overridable via the manifest's
// createRepo.name) and commits the rendered skeleton tree. Idempotent: a
// step result with repoUrl skips EnsureRepo/CommitFiles entirely.
func stepCreatingRepo(ctx context.Context, env *ExecEnv, rc *RunContext, step *types.ScaffoldRunStep) (bool, error) {
	var prev createRepoResult
	if len(step.Result) > 0 {
		if err := json.Unmarshal(step.Result, &prev); err == nil && prev.RepoURL != "" {
			return true, nil
		}
	}
	if env == nil || env.Git == nil {
		return false, errors.New("scaffold: no git provider configured")
	}
	if env.GitOrg == "" {
		return false, errors.New("scaffold: no git org configured (INARI_SCAFFOLD_GIT_ORG)")
	}
	if rc.Tenant == nil || rc.Tenant.Slug == "" {
		return false, errors.New("scaffold: tenant context required for repo naming")
	}
	rendering := rc.Steps["rendering"]
	var rendered renderResult
	if rendering == nil || len(rendering.Result) == 0 ||
		json.Unmarshal(rendering.Result, &rendered) != nil || len(rendered.Files) == 0 {
		return false, errors.New("scaffold: rendering step result missing")
	}
	component, err := componentName(rc)
	if err != nil {
		return false, err
	}
	pkg, err := templatePackage(env, rc)
	if err != nil {
		return false, err
	}
	branch := manifestParam(&pkg.Manifest, "createRepo", "defaultBranch", "main")
	segment := manifestParam(&pkg.Manifest, "createRepo", "name", rc.Tenant.Slug+"-"+component)
	if segment != filepath.Base(segment) || segment == "." || segment == ".." || strings.Contains(segment, `\`) {
		return false, fmt.Errorf("scaffold: invalid createRepo.name %q", segment)
	}
	repo := env.GitOrg + "/" + segment
	cloneURL, err := env.Git.EnsureRepo(ctx, repo)
	if err != nil {
		return false, fmt.Errorf("scaffold: ensure repo %s: %w", repo, err)
	}
	files := make([]gitprovider.File, 0, len(rendered.Files))
	for _, f := range rendered.Files {
		files = append(files, gitprovider.File{Path: f.Path, Content: []byte(f.Content)})
	}
	res, err := env.Git.CommitFiles(ctx, repo, branch, files, fmt.Sprintf("scaffold: initial %s skeleton", component))
	if err != nil {
		return false, fmt.Errorf("scaffold: commit skeleton to %s: %w", repo, err)
	}
	raw, err := json.Marshal(createRepoResult{RepoName: repo, RepoURL: cloneURL, Branch: branch, CommitSHA: res.CommitSHA})
	if err != nil {
		return false, err
	}
	step.Result = raw
	if err := mergeOutputs(rc, "repoUrl", cloneURL); err != nil {
		return false, err
	}
	return true, nil
}

// stepCreatingPipeline registers the component's ArgoCD Application with
// the tenant cluster's agent (pull model — the CI file itself ships in the
// skeleton commit). Only the github-actions pipeline kind is supported in
// this slice. Idempotent: a step result with applicationName skips the
// enqueue; the command ID is the run ID so agent-side dedup makes a retry
// safe anyway.
func stepCreatingPipeline(ctx context.Context, env *ExecEnv, rc *RunContext, step *types.ScaffoldRunStep) (bool, error) {
	var prev createPipelineResult
	if len(step.Result) > 0 {
		if err := json.Unmarshal(step.Result, &prev); err == nil && prev.ApplicationName != "" {
			return true, nil
		}
	}
	if env == nil || env.Registrar == nil {
		return false, errors.New("scaffold: no app registrar configured")
	}
	if rc.Tenant == nil {
		return false, errors.New("scaffold: tenant context required")
	}
	if rc.Tenant.ClusterID == "" {
		return false, errors.New("scaffold: no cluster registered for tenant")
	}
	repoStep := rc.Steps["creating-repo"]
	var repo createRepoResult
	if repoStep == nil || len(repoStep.Result) == 0 ||
		json.Unmarshal(repoStep.Result, &repo) != nil || repo.RepoURL == "" {
		return false, errors.New("scaffold: creating-repo step result missing")
	}
	component, err := componentName(rc)
	if err != nil {
		return false, err
	}
	pkg, err := templatePackage(env, rc)
	if err != nil {
		return false, err
	}
	if provider := manifestParam(&pkg.Manifest, "createPipeline", "provider", "github-actions"); provider != "github-actions" {
		return false, fmt.Errorf("scaffold: unsupported pipeline provider %q (only github-actions)", provider)
	}
	path := manifestParam(&pkg.Manifest, "createPipeline", "path", "k8s")
	project := manifestParam(&pkg.Manifest, "createPipeline", "project", "default")
	branch := repo.Branch
	if branch == "" {
		branch = "main"
	}
	appName := "inari-" + component
	manifest := orchestrator.RenderArgoCDApplication(orchestrator.ApplicationParams{
		Name:           appName,
		Project:        project,
		RepoURL:        repo.RepoURL,
		Path:           path,
		TargetRevision: branch,
		DestNamespace:  rc.Tenant.Namespace,
	})
	cmd := &agentv1.RegisterArgoCDApp{
		CommandId: rc.Run.ID,
		Name:      appName,
		Project:   project,
		Source: &agentv1.ApplicationSource{
			RepoUrl:        repo.RepoURL,
			Path:           path,
			TargetRevision: branch,
		},
		DestinationServer:    "https://kubernetes.default.svc",
		DestinationNamespace: rc.Tenant.Namespace,
		SyncPolicy:           &agentv1.SyncPolicy{Automated: true, SelfHeal: true, Prune: true},
	}
	if err := enqueueRegisterApp(ctx, env.Registrar, rc.Tenant.ClusterID, rc.Run.ID, cmd); err != nil {
		return false, err
	}
	pipelineURL := strings.TrimSuffix(repo.RepoURL, ".git") + "/actions"
	raw, err := json.Marshal(createPipelineResult{
		ApplicationName: appName, PipelineURL: pipelineURL,
		ClusterID: rc.Tenant.ClusterID, Application: string(manifest),
	})
	if err != nil {
		return false, err
	}
	step.Result = raw
	if err := mergeOutputs(rc, "pipelineUrl", pipelineURL); err != nil {
		return false, err
	}
	return true, nil
}

// enqueueRegisterApp wraps agentv1.RegisterArgoCDApp for the agent command
// queue (same anypb + protojson envelope as
// orchestrator.enqueueAppRegistration). Command ID = "register-argocd-app:"
// + id → agent-side idempotent re-delivery.
func enqueueRegisterApp(ctx context.Context, reg AppRegistrar, clusterID, id string, cmd *agentv1.RegisterArgoCDApp) error {
	any, err := anypb.New(cmd)
	if err != nil {
		return err
	}
	raw, err := protojson.Marshal(any)
	if err != nil {
		return err
	}
	return reg.Enqueue(ctx, &types.AgentCommand{
		ID:        "register-argocd-app:" + id,
		ClusterID: clusterID,
		Type:      agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_REGISTER_ARGOCD_APP),
		Payload:   raw,
	})
}
