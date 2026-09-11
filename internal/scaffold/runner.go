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
}

// TenantContextResolver resolves a run's org into its render context
// (tenancy.Service seam; scaffold runs carry OrgID, not the slug).
type TenantContextResolver interface {
	ResolveTenant(ctx context.Context, orgID string) (*TenantContext, error)
}

// ExecEnv bundles the backend seams the steps run against. Git, Upsert,
// Groups and Registrar are consumed by the W4 phase steps; Templates and
// Tenants by the rendering step. All are optional — a nil seam makes the
// depending step fail, not the engine.
type ExecEnv struct {
	Git       GitProvider
	Upsert    CatalogUpserter
	Groups    GroupBinder
	Registrar AppRegistrar
	Templates *FilePuller
	Tenants   TenantContextResolver
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

// stepWaitingPlaceholder parks a run at a phase whose executor ships in W4
// (plan Decision 2): waiting consumes no attempt budget, so replacing the
// placeholder lets parked runs proceed on the next reconcile tick.
func stepWaitingPlaceholder(context.Context, *ExecEnv, *RunContext, *types.ScaffoldRunStep) (bool, error) {
	return false, nil
}

// stepFuncs is the phase execution table (plan §3: phases map 1:1 to
// steps). Only rendering is real in W3; the remaining entries are W4
// placeholders.
var stepFuncs = map[string]StepFunc{
	"rendering":           stepRendering,
	"creating-repo":       stepWaitingPlaceholder,
	"creating-pipeline":   stepWaitingPlaceholder,
	"registering-catalog": stepWaitingPlaceholder,
	"binding-rbac":        stepWaitingPlaceholder,
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
