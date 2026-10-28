// The kind: gitops-repo pipeline steps (Feature B, parent plan §5):
// registering-repo inserts the team-scoped row into the org's repo
// registry (tenant_git_repos); attaching-root-app commits the team repo's
// root Application into the org's baseline repo and enqueues the agent
// RegisterArgoCDApp command so the team repo goes live. Both steps follow
// the established idempotency convention: a persisted step result
// short-circuits re-entry.
package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/gitrepos"
	"github.com/7K-Inari/inari-server/internal/impersonation"
	"github.com/7K-Inari/inari-server/internal/types"
)

// registerRepoResult is the shape persisted in scaffold_run_steps.result
// for the registering-repo step; attaching-root-app consumes it.
type registerRepoResult struct {
	RepoID string `json:"repoId"`
	Repo   string `json:"repo"`
	TeamID string `json:"teamId"`
}

// attachRootAppResult is the shape persisted for the attaching-root-app
// step. When the org has no baseline repo yet AttachRootApp skips the
// baseline commit (the root app can be committed once a baseline exists);
// RootAppPath still records the intended path and the agent command is
// still enqueued.
type attachRootAppResult struct {
	RootAppPath     string `json:"rootAppPath,omitempty"`
	ApplicationName string `json:"applicationName"`
	ClusterID       string `json:"clusterId"`
}

// gitopsRepoValues are the wizard answers the gitops-repo pipeline reads
// (templates/gitops-repo/schema.json).
type gitopsRepoValues struct {
	RepoName     string
	Team         string
	GitOrg       string
	CommitPolicy string
	BaseBranch   string
}

// gitopsValues decodes the run's wizard values for a kind: gitops-repo
// run. RepoName and Team are schema-required; the decode here is the
// step-level defense.
func gitopsValues(rc *RunContext) (*gitopsRepoValues, error) {
	var v struct {
		RepoName     string `json:"repoName"`
		Team         string `json:"team"`
		GitOrg       string `json:"gitOrg"`
		CommitPolicy string `json:"commitPolicy"`
		BaseBranch   string `json:"baseBranch"`
	}
	if len(rc.Run.Values) > 0 {
		if err := json.Unmarshal(rc.Run.Values, &v); err != nil {
			return nil, fmt.Errorf("scaffold: decode run values: %w", err)
		}
	}
	if v.RepoName == "" {
		return nil, errors.New("scaffold: values.repoName is required for gitops-repo runs")
	}
	if v.Team == "" {
		return nil, errors.New("scaffold: values.team is required for gitops-repo runs")
	}
	return &gitopsRepoValues{
		RepoName:     v.RepoName,
		Team:         v.Team,
		GitOrg:       v.GitOrg,
		CommitPolicy: v.CommitPolicy,
		BaseBranch:   v.BaseBranch,
	}, nil
}

// resolveOwningTeam maps the wizard's team answer onto the existing tenant
// team row (the wizard offers a dropdown of existing teams).
func resolveOwningTeam(ctx context.Context, env *ExecEnv, rc *RunContext, teamName string) (*types.Team, error) {
	if env == nil || env.Teams == nil {
		return nil, errors.New("scaffold: no team lookup configured")
	}
	if rc.Tenant == nil || rc.Tenant.Slug == "" {
		return nil, errors.New("scaffold: tenant context required for team resolution")
	}
	team, err := env.Teams.GetTeamByName(ctx, rc.Tenant.Slug, teamName)
	if err != nil {
		return nil, fmt.Errorf("scaffold: resolve owning team %q: %w", teamName, err)
	}
	if team == nil {
		return nil, fmt.Errorf("scaffold: owning team %q not found in tenant %s", teamName, rc.Tenant.Slug)
	}
	return team, nil
}

// stepRegisteringRepo inserts the team-scoped row into the org's repo
// registry (Feature B): scope=team, team_id from the wizard's owning
// team, commit policy + base branch from the wizard, provider=github.
// The repo slug comes from the creating-repo step result so the row
// always matches the created repo. Idempotent: a persisted result with
// repoId skips the call entirely.
func stepRegisteringRepo(ctx context.Context, env *ExecEnv, rc *RunContext, step *types.ScaffoldRunStep) (bool, error) {
	var prev registerRepoResult
	if len(step.Result) > 0 {
		if err := json.Unmarshal(step.Result, &prev); err == nil && prev.RepoID != "" {
			return true, nil
		}
	}
	if env == nil || env.GitRepos == nil {
		return false, errors.New("scaffold: no git repo registrar configured")
	}
	repoStep := rc.Steps["creating-repo"]
	var repo createRepoResult
	if repoStep == nil || len(repoStep.Result) == 0 ||
		json.Unmarshal(repoStep.Result, &repo) != nil || repo.RepoName == "" {
		return false, errors.New("scaffold: creating-repo step result missing")
	}
	values, err := gitopsValues(rc)
	if err != nil {
		return false, err
	}
	team, err := resolveOwningTeam(ctx, env, rc, values.Team)
	if err != nil {
		return false, err
	}
	// The run engine drives steps as the system:scaffold actor; the
	// registry's audit path requires automation to impersonate the
	// tenant-scoped virtual user (plan §5.4).
	ctx = impersonation.WithImpersonator(ctx, impersonation.VirtualUser(rc.Run.OrgID))
	row, err := env.GitRepos.RegisterTeamRepo(ctx, rc.Run.OrgID, gitrepos.RegisterInput{
		Name:         values.RepoName,
		Repo:         repo.RepoName,
		Provider:     string(types.GitRepoProviderGitHub),
		Scope:        types.GitRepoScopeTeam,
		TeamID:       team.ID,
		CommitPolicy: types.CommitPolicy(values.CommitPolicy),
		BaseBranch:   values.BaseBranch,
	}, rc.Actor)
	if err != nil {
		return false, fmt.Errorf("scaffold: register repo %s: %w", repo.RepoName, err)
	}
	raw, err := json.Marshal(registerRepoResult{RepoID: row.ID, Repo: row.Repo, TeamID: row.TeamID})
	if err != nil {
		return false, err
	}
	step.Result = raw
	if err := mergeOutputs(rc, "gitRepoId", row.ID); err != nil {
		return false, err
	}
	return true, nil
}

// stepAttachingRootApp commits the team repo's root Application into the
// org's baseline repo (gitops-repos/<name>/root-app.yaml — the baseline
// root app already syncs that path, so ArgoCD pulls the team repo) and
// enqueues RegisterArgoCDApp for the team repo's own root application
// (<repoName>-root from the skeleton) against the tenant's cluster.
// Idempotent: a persisted result with applicationName skips both calls;
// AttachRootApp is itself idempotent (same-content recommit) and the
// command ID is the run ID so agent-side dedup makes a retry safe.
func stepAttachingRootApp(ctx context.Context, env *ExecEnv, rc *RunContext, step *types.ScaffoldRunStep) (bool, error) {
	var prev attachRootAppResult
	if len(step.Result) > 0 {
		if err := json.Unmarshal(step.Result, &prev); err == nil && prev.ApplicationName != "" {
			return true, nil
		}
	}
	if env == nil || env.RootApp == nil {
		return false, errors.New("scaffold: no root-app attacher configured")
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
	regStep := rc.Steps["registering-repo"]
	var reg registerRepoResult
	if regStep == nil || len(regStep.Result) == 0 ||
		json.Unmarshal(regStep.Result, &reg) != nil || reg.RepoID == "" {
		return false, errors.New("scaffold: registering-repo step result missing")
	}
	values, err := gitopsValues(rc)
	if err != nil {
		return false, err
	}
	branch := repo.Branch
	if branch == "" {
		branch = "main"
	}
	// Commit the root app into the baseline repo. When the org has no
	// default baseline yet the attach is skipped (M1 semantics) — the team
	// repo goes live once a baseline exists; the run still succeeds.
	row := &types.TenantGitRepo{
		ID: reg.RepoID, OrgID: rc.Run.OrgID, Name: values.RepoName, Repo: repo.RepoName,
		Provider: types.GitRepoProviderGitHub, Scope: types.GitRepoScopeTeam, TeamID: reg.TeamID,
		BaseBranch: branch,
	}
	if err := env.RootApp.AttachRootApp(ctx, rc.Run.OrgID, row); err != nil {
		return false, fmt.Errorf("scaffold: attach root app for %s: %w", repo.RepoName, err)
	}
	rootAppPath := gitrepos.RootAppPath(values.RepoName)
	// Register the team repo's own root application with the tenant
	// cluster's agent so the repo reconciles immediately.
	appName := values.RepoName + "-root"
	cmd := &agentv1.RegisterArgoCDApp{
		CommandId: rc.Run.ID,
		Name:      appName,
		Project:   "default",
		Source: &agentv1.ApplicationSource{
			RepoUrl:        repo.RepoURL,
			Path:           ".",
			TargetRevision: branch,
		},
		DestinationServer:    "https://kubernetes.default.svc",
		DestinationNamespace: "argocd",
		SyncPolicy:           &agentv1.SyncPolicy{Automated: true, SelfHeal: true, Prune: true},
	}
	if err := enqueueRegisterApp(ctx, env.Registrar, rc.Tenant.ClusterID, rc.Run.ID, cmd); err != nil {
		return false, err
	}
	raw, err := json.Marshal(attachRootAppResult{
		RootAppPath: rootAppPath, ApplicationName: appName, ClusterID: rc.Tenant.ClusterID,
	})
	if err != nil {
		return false, err
	}
	step.Result = raw
	if err := mergeOutputs(rc, "rootAppPath", rootAppPath); err != nil {
		return false, err
	}
	return true, nil
}
