// The resumable, idempotent zone state machine (plan §5.12, §10). Steps
// run in order against the backend seams; async operations persist their
// handle in step.ExternalRef so a restart resumes polling instead of
// re-creating. This file is deliberately DB-free: persistence/audit/outbox
// is the Service's job via the OnUpdate callback.
package tenantzonefactory

import (
	"context"
	"errors"

	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrPreflightDenied marks permanent pre-flight rejection (no retry).
var ErrPreflightDenied = errors.New("tzf: pre-flight denied")

// Config carries the TZF knobs (populated from internal/config INARI_TZF_*).
type Config struct {
	ApprovalRequired bool
	AccountQuota     int // max accounts per OU (§10 quota pre-check)
	AllowedRegions   []string
	AllowedTiers     []string
	RequiredTags     []string // mandatory cost/allocation tag keys
	IssuerURL        string   // platform OIDC issuer for trust bootstrap
	MaxAttempts      int      // per-step attempts before manual_intervention
}

// ClusterLifecycle is the clusterregistry seam used by the decommission
// path (cordon + ownership-checked drain + identity revocation).
type ClusterLifecycle interface {
	Cordon(ctx context.Context, actor, clusterID string) error
	Decommission(ctx context.Context, actor, clusterID string, force bool) (drained []string, err error)
}

// Wiring is the Inari-wiring seam (plan §5.12 step 5): Keycloak
// Organization + default groups/RBAC, Cluster + CloudAccount records,
// registration token, and the tenant-zone baseline bundle rendered into
// the zone's Git repo with the ArgoCD root app registered.
type Wiring interface {
	WireZone(ctx context.Context, zone *types.TenantZone) (*WiringResult, error)
	UnwireZone(ctx context.Context, zone *types.TenantZone) error
}

// WiringResult carries the records created by WireZone back to the zone.
type WiringResult struct {
	OrgID          string
	KeycloakOrgID  string
	ClusterID      string
	CloudAccountID string
	GitRepo        string
}

// Env bundles the backend seams the steps run against.
type Env struct {
	AWS       Organizations
	Bootstrap TrustBootstrap
	Prov      Provisioner
	Wiring    Wiring
	Clusters  ClusterLifecycle
	Config    Config
}

// ProvisionOrder is the vending step sequence (plan §5.12 steps 1-5).
var ProvisionOrder = []string{
	types.ZoneStepPreflight,
	types.ZoneStepAccountVend,
	types.ZoneStepTrustBootstrap,
	types.ZoneStepEKSProvision,
	types.ZoneStepInariWiring,
}

// DecommissionOrder reverses the flow (plan §5.12 lifecycle ties).
var DecommissionOrder = []string{
	types.ZoneStepCordon,
	types.ZoneStepDrain,
	types.ZoneStepEKSDelete,
	types.ZoneStepAccountClose,
	types.ZoneStepIdentityRevoke,
	types.ZoneStepAuditArchive,
}

// StepFunc runs one step idempotently. done=false means an async operation
// is in flight (step waits; the runner is re-entered later). err is a hard
// failure counted against the step's attempt budget.
type StepFunc func(ctx context.Context, env *Env, rc *RunContext, step *types.TenantZoneStep) (done bool, err error)

// RunContext gives steps access to the zone and sibling steps (e.g.
// eks_delete needs the MR ref recorded by eks_provision).
type RunContext struct {
	Zone  *types.TenantZone
	Steps map[string]*types.TenantZoneStep
	Actor string
}

// OnUpdate persists a mutated step (and the zone) after each transition;
// the Service supplies TX + audit + outbox.
type OnUpdate func(ctx context.Context, rc *RunContext, step *types.TenantZoneStep) error

var provisionSteps = map[string]StepFunc{
	types.ZoneStepPreflight:      stepPreflight,
	types.ZoneStepAccountVend:    stepAccountVend,
	types.ZoneStepTrustBootstrap: stepTrustBootstrap,
	types.ZoneStepEKSProvision:   stepEKSProvision,
	types.ZoneStepInariWiring:    stepInariWiring,
}

var decommissionSteps = map[string]StepFunc{
	types.ZoneStepCordon:         stepCordon,
	types.ZoneStepDrain:          stepDrain,
	types.ZoneStepEKSDelete:      stepEKSDelete,
	types.ZoneStepAccountClose:   stepAccountClose,
	types.ZoneStepIdentityRevoke: stepIdentityRevoke,
	types.ZoneStepAuditArchive:   stepAuditArchive,
}

// RunSteps executes the remaining steps of order against env. It stops at
// the first waiting (async) or failed step and reports whether every step
// succeeded.
func RunSteps(ctx context.Context, env *Env, order []string, funcs map[string]StepFunc, rc *RunContext, onUpdate OnUpdate) (complete bool, err error) {
	for _, name := range order {
		st := rc.Steps[name]
		if st == nil {
			st = &types.TenantZoneStep{ZoneID: rc.Zone.ID, Step: name, Status: types.ZoneStepPending}
			rc.Steps[name] = st
		}
		if st.Status == types.ZoneStepSucceeded || st.Status == types.ZoneStepSkipped {
			continue
		}
		st.Attempts++
		st.Status = types.ZoneStepRunning
		done, stepErr := funcs[name](ctx, env, rc, st)
		switch {
		case stepErr != nil:
			st.Status = types.ZoneStepFailed
			if uerr := onUpdate(ctx, rc, st); uerr != nil {
				return false, uerr
			}
			return false, stepErr
		case !done:
			st.Status = types.ZoneStepWaiting
			if uerr := onUpdate(ctx, rc, st); uerr != nil {
				return false, uerr
			}
			return false, nil
		default:
			st.Status = types.ZoneStepSucceeded
			if uerr := onUpdate(ctx, rc, st); uerr != nil {
				return false, uerr
			}
		}
	}
	return true, nil
}
