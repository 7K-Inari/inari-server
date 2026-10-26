// The resumable, idempotent scaffold-run state machine (M8.W3, plan
// §5.1/§5.2): steps run in phase order against the ExecEnv seams;
// completed steps persist their output in step.Result so a restart resumes
// instead of re-executing. This file is deliberately DB-free:
// persistence/audit/outbox is the Service's job via the OnUpdate callback
// (adapted from internal/tenantzonefactory/runner.go).
package scaffold

import (
	"context"
	"errors"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/gitrepos"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrCancelled marks cooperative cancellation observed between steps; the
// Service settles the run to failed with error=cancelled.
var ErrCancelled = errors.New("scaffold: run cancelled")

// TenantContext is the per-run tenant projection exposed to templates as
// .Tenant. Namespace follows the TZF tenant-namespace convention (the slug
// doubles as the tenant namespace); GroupPath is the tenant members group
// (tenant-<slug>/members, see tenancy.membersTeamName).
type TenantContext struct {
	Slug      string `json:"slug"`
	OrgID     string `json:"orgId"`
	Namespace string `json:"namespace"`
	GroupPath string `json:"groupPath"`
	// ClusterID is the tenant's target cluster for ArgoCD app
	// registration (slice 1: the tenant's first registered cluster).
	ClusterID string `json:"clusterId,omitempty"`
}

// TenantContextResolver resolves a run's org into its render context
// (tenancy.Service seam; scaffold runs carry OrgID, not the slug).
type TenantContextResolver interface {
	ResolveTenant(ctx context.Context, orgID string) (*TenantContext, error)
}

// ApprovalGate evaluates approval policy for a gated template run
// (approvals.Service subset; plan §5.3 — same seam the orchestrator uses).
type ApprovalGate interface {
	Gate(ctx context.Context, in approvals.GateInput) (*approvals.GateResult, error)
}

// GitConfigResolver resolves a tenant's git config (inventory.Store
// subset via adapter; nil config means no per-tenant row).
type GitConfigResolver interface {
	GitConfigForOrg(ctx context.Context, orgID string) (*types.TenantGitConfig, error)
}

// UserGitResolver resolves a git provider bound to one user's connected
// git identity (M8.W6 user-scoped templates; gitprovider.Resolver.ForUser,
// model C). Implementations fail closed: a missing connection is a typed
// error, never a silent platform fallback.
type UserGitResolver interface {
	ForUser(ctx context.Context, orgID, userSub string) (gitprovider.Provider, *gitprovider.AuthInfo, error)
}

// GitFallback describes one applied user-scope → platform-app fallback
// (the tenant's userTemplateFallback=platform_app policy).
type GitFallback struct {
	UserSub string // initiating user (run.CreatedBy)
	// Reason classifies the failed user resolution: no_connection |
	// user_model_unsupported.
	Reason string
}

// GitFallbackHook is invoked once when a user-scoped template run falls
// back to the platform app; the Service supplies audit + outbox.
type GitFallbackHook func(ctx context.Context, rc *RunContext, fb GitFallback) error

// GitRepoRegistrar registers a team-scoped repo row in the org's repo
// registry (Feature B registering-repo step; gitrepos.Service subset).
// Implementations validate + insert + audit but do NOT attach the root
// app — that is the attaching-root-app step's job.
type GitRepoRegistrar interface {
	RegisterTeamRepo(ctx context.Context, orgID string, in gitrepos.RegisterInput, actor string) (*types.TenantGitRepo, error)
}

// RootAppAttacher commits a team repo's root Application into the org's
// baseline repo (Feature B attaching-root-app step; gitrepos.Service
// subset).
type RootAppAttacher interface {
	AttachRootApp(ctx context.Context, orgID string, row *types.TenantGitRepo) error
}

// TeamLookup resolves an existing tenant team by name (Feature B: the
// gitops-repo wizard picks an owning team; tenancy.Service subset).
type TeamLookup interface {
	GetTeamByName(ctx context.Context, slug, name string) (*types.Team, error)
}

// ExecEnv bundles the backend seams the steps run against. Git, Upsert,
// RBAC and Registrar are consumed by the W4 phase steps; Templates and
// Tenants by the rendering step; Gate by the W6 approval hold; GitConfigs
// by the W6 per-tenant git org override; GitRepos/RootApp/Teams by the
// Feature B gitops-repo steps. All are optional — a nil seam makes the
// depending step fail, not the engine.
type ExecEnv struct {
	Git        GitProvider
	GitOrg     string // git organization/owner receiving scaffolded repos
	Upsert     CatalogUpserter
	RBAC       RBACBinder
	Registrar  AppRegistrar
	Templates  TemplateSource
	Tenants    TenantContextResolver
	Gate       ApprovalGate
	GitConfigs GitConfigResolver
	// GitRepos registers team repos (kind: gitops-repo runs).
	GitRepos GitRepoRegistrar
	// RootApp attaches team-repo root Applications to the baseline repo.
	RootApp RootAppAttacher
	// Teams resolves existing teams by name (kind: gitops-repo runs).
	Teams TeamLookup
	// UserGit resolves per-user git providers for user-scoped templates
	// (nil → user scope behaves as "no connection": the tenant fallback
	// policy decides).
	UserGit UserGitResolver
	// OnGitFallback is invoked when a user-scoped run falls back to the
	// platform app (audit seam; nil → no audit record).
	OnGitFallback GitFallbackHook
}

// StepFunc runs one step idempotently. done=false means the step is
// waiting (async in flight or a W4 placeholder) and does NOT consume the
// attempt budget; err is a hard failure counted against the budget.
type StepFunc func(ctx context.Context, env *ExecEnv, rc *RunContext, step *types.ScaffoldRunStep) (done bool, err error)

// RunContext gives steps access to the run, sibling steps and the
// resolved tenant.
type RunContext struct {
	Run    *types.ScaffoldRun
	Steps  map[string]*types.ScaffoldRunStep
	Tenant *TenantContext
	Actor  string
}

// OnUpdate persists a mutated step (and the run) after each transition;
// the Service supplies TX + audit + outbox.
type OnUpdate func(ctx context.Context, rc *RunContext, step *types.ScaffoldRunStep) error

// stepFuncs is the phase execution table (plan §3: phases map 1:1 to
// steps). Rendering (W3) and the four phase steps (W4) are all real.
var stepFuncs = map[string]StepFunc{
	"rendering":           stepRendering,
	"creating-repo":       stepCreatingRepo,
	"creating-pipeline":   stepCreatingPipeline,
	"registering-catalog": stepRegisteringCatalog,
	"registering-repo":    stepRegisteringRepo,
	"attaching-root-app":  stepAttachingRootApp,
	"binding-rbac":        stepBindingRBAC,
}

// RunSteps executes the remaining steps of order. It stops at the first
// waiting or failed step (or when isCancelled reports a cooperative
// cancel) and reports whether every step completed.
func RunSteps(ctx context.Context, env *ExecEnv, rc *RunContext, order []string, funcs map[string]StepFunc, onUpdate OnUpdate, isCancelled func() bool) (complete bool, err error) {
	for _, name := range order {
		st := rc.Steps[name]
		if st == nil {
			st = &types.ScaffoldRunStep{RunID: rc.Run.ID, Name: name, State: types.ScaffoldStepPending}
			rc.Steps[name] = st
		}
		if st.State == types.ScaffoldStepCompleted {
			continue
		}
		if isCancelled != nil && isCancelled() {
			st.State = types.ScaffoldStepFailed
			st.Error = "cancelled"
			if uerr := onUpdate(ctx, rc, st); uerr != nil {
				return false, uerr
			}
			return false, ErrCancelled
		}
		st.State = types.ScaffoldStepRunning
		done, stepErr := funcs[name](ctx, env, rc, st)
		switch {
		case stepErr != nil:
			st.Attempts++ // only genuine failures consume the attempt budget, not waits
			st.Error = stepErr.Error()
			st.State = types.ScaffoldStepFailed
			if uerr := onUpdate(ctx, rc, st); uerr != nil {
				return false, uerr
			}
			return false, stepErr
		case !done:
			st.State = types.ScaffoldStepWaiting
			if uerr := onUpdate(ctx, rc, st); uerr != nil {
				return false, uerr
			}
			return false, nil
		default:
			st.Error = ""
			st.State = types.ScaffoldStepCompleted
			if uerr := onUpdate(ctx, rc, st); uerr != nil {
				return false, uerr
			}
		}
	}
	return true, nil
}
