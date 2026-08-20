// Package tenantzonefactory implements the Tenant Zone Factory module
// (plan §5.12): a platform-engineer-only, approval- and policy-gated flow
// that vends a new AWS organization account, bootstraps OIDC trust,
// provisions an EKS cluster, wires the zone into Inari (Keycloak
// Organization, Cluster + CloudAccount records, registration token,
// baseline bundle in the zone's Git repo), and flips it Active. The flow
// is a resumable, idempotent state machine; decommission reverses it
// behind the same gates with §10 ownership checks.
package tenantzonefactory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrInvalidState is returned for operations a zone's state does not allow.
var ErrInvalidState = errors.New("tzf: zone in invalid state")

// LifecycleGate creates lifecycle approval requests (approvals.Service).
type LifecycleGate interface {
	RequestLifecycleApproval(ctx context.Context, in approvals.LifecycleApprovalInput) (*types.ApprovalRequest, error)
}

// Service orchestrates zone vending and decommission: DB projection +
// audit + outbox in TXs around the DB-free step runner.
type Service struct {
	db    *db.DB
	store *Store
	audit *audit.Store
	env   *Env
	gate  LifecycleGate
	log   *slog.Logger
	newID func() string
}

// NewService builds the module service. env carries the backend seams
// (fake by default); gate may be nil when approvals are disabled.
func NewService(d *db.DB, store *Store, auditStore *audit.Store, env *Env, gate LifecycleGate, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	if env.Config.MaxAttempts <= 0 {
		env.Config.MaxAttempts = 5
	}
	return &Service{db: d, store: store, audit: auditStore, env: env, gate: gate, log: log, newID: newUUID}
}

// RequestInput is the zone vending form (plan §5.12 step 1).
type RequestInput struct {
	Slug                string
	DisplayName         string
	OUID                string
	Region              string
	Tier                string
	Tags                map[string]string
	ManagementAccountID string // cloud_accounts.id with scope: management
	OwnerOrgID          string // org owning the management account
}

// RequestResult reports the created zone and, when gated, the approval.
type RequestResult struct {
	Zone       *types.TenantZone
	ApprovalID string // set when pending approval
}

// RequestZone validates the request, persists the zone, and either gates
// it on a platform-admin approval (default policy) or starts provisioning.
func (s *Service) RequestZone(ctx context.Context, actor string, in RequestInput) (*RequestResult, error) {
	if in.ManagementAccountID == "" || in.OwnerOrgID == "" {
		return nil, fmt.Errorf("tzf: management cloud account and owner org are required (§5.12 prerequisite)")
	}
	zone := &types.TenantZone{
		ID: "zone:" + s.newID(), Slug: in.Slug, DisplayName: in.DisplayName,
		OwnerOrgID: in.OwnerOrgID, OUID: in.OUID, Region: in.Region, Tier: in.Tier,
		Tags: in.Tags, State: types.ZoneStateRequested, ManagementAccountID: in.ManagementAccountID,
		CreatedBy: actor,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateZone(ctx, tx, zone); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: in.OwnerOrgID, Actor: actor, Action: "tenant_zone.requested",
			ObjectType: "tenant_zone", ObjectID: zone.ID,
			Payload: json.RawMessage(fmt.Sprintf(`{"slug":%q,"ouId":%q,"region":%q,"tier":%q}`, in.Slug, in.OUID, in.Region, in.Tier)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, in.OwnerOrgID, types.EventTenantZoneRequested, types.TenantZonePayload{
			OrgID: in.OwnerOrgID, ZoneID: zone.ID, Slug: zone.Slug, State: string(zone.State),
		})
	})
	if err != nil {
		return nil, err
	}
	res := &RequestResult{Zone: zone}
	if s.env.Config.ApprovalRequired {
		if s.gate == nil {
			return nil, fmt.Errorf("tzf: approvals required but no gate configured")
		}
		reqCtx, _ := json.Marshal(map[string]string{"zoneId": zone.ID, "slug": zone.Slug})
		req, err := s.gate.RequestLifecycleApproval(ctx, approvals.LifecycleApprovalInput{
			OrgID: in.OwnerOrgID, Action: types.ApprovalActionTenantZoneVend,
			Requester: actor, Context: reqCtx,
		})
		if err != nil {
			return nil, err
		}
		if err := s.setState(ctx, zone, types.ZoneStatePendingApproval, ""); err != nil {
			return nil, err
		}
		res.ApprovalID = req.ID
		return res, nil
	}
	if err := s.StartProvisioning(ctx, zone.ID, actor); err != nil {
		return nil, err
	}
	return res, nil
}

// StartProvisioning flips a zone to provisioning and runs the step chain
// (called post-approval or directly when approvals are disabled).
func (s *Service) StartProvisioning(ctx context.Context, zoneID, actor string) error {
	zone, err := s.store.GetZone(ctx, s.db.Pool, zoneID)
	if err != nil {
		return err
	}
	switch zone.State {
	case types.ZoneStateRequested, types.ZoneStatePendingApproval, types.ZoneStateProvisioning,
		types.ZoneStateManualIntervention:
	default:
		return fmt.Errorf("%w: cannot provision from %s", ErrInvalidState, zone.State)
	}
	if err := s.setState(ctx, zone, types.ZoneStateProvisioning, ""); err != nil {
		return err
	}
	return s.run(ctx, zone, actor, ProvisionOrder, provisionSteps)
}

// ResumeZone re-enters the runner after manual intervention (§10).
func (s *Service) ResumeZone(ctx context.Context, zoneID, actor string) error {
	zone, err := s.store.GetZone(ctx, s.db.Pool, zoneID)
	if err != nil {
		return err
	}
	switch zone.State {
	case types.ZoneStateProvisioning, types.ZoneStateWiring, types.ZoneStateManualIntervention, types.ZoneStateFailed:
		return s.run(ctx, zone, actor, ProvisionOrder, provisionSteps)
	case types.ZoneStateCordoning, types.ZoneStateDraining, types.ZoneStateDecommissioning:
		return s.run(ctx, zone, actor, DecommissionOrder, decommissionSteps)
	default:
		return fmt.Errorf("%w: cannot resume from %s", ErrInvalidState, zone.State)
	}
}

// RequestDecommission gates zone teardown on a platform-admin approval
// (plan §5.12 lifecycle ties). The reverse flow starts on approval.
func (s *Service) RequestDecommission(ctx context.Context, actor, zoneID string) (string, error) {
	zone, err := s.store.GetZone(ctx, s.db.Pool, zoneID)
	if err != nil {
		return "", err
	}
	if zone.State != types.ZoneStateActive && zone.State != types.ZoneStateFailed {
		return "", fmt.Errorf("%w: cannot decommission from %s", ErrInvalidState, zone.State)
	}
	if !s.env.Config.ApprovalRequired || s.gate == nil {
		if err := s.StartDecommission(ctx, zoneID, actor); err != nil {
			return "", err
		}
		return "", nil
	}
	reqCtx, _ := json.Marshal(map[string]string{"zoneId": zone.ID, "slug": zone.Slug})
	req, err := s.gate.RequestLifecycleApproval(ctx, approvals.LifecycleApprovalInput{
		OrgID: zone.OwnerOrgID, Action: types.ApprovalActionTenantZoneDecommission,
		Requester: actor, Context: reqCtx,
	})
	if err != nil {
		return "", err
	}
	if err := s.setState(ctx, zone, types.ZoneStateDecommissionPendingApproval, ""); err != nil {
		return "", err
	}
	if err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return audit.AppendOutbox(ctx, tx, zone.OwnerOrgID, types.EventTenantZoneDecommissionRequested, types.TenantZonePayload{
			OrgID: zone.OwnerOrgID, ZoneID: zone.ID, Slug: zone.Slug, State: string(types.ZoneStateDecommissionPendingApproval),
		})
	}); err != nil {
		return "", err
	}
	return req.ID, nil
}

// StartDecommission begins the reverse flow (post-approval or ungated).
func (s *Service) StartDecommission(ctx context.Context, zoneID, actor string) error {
	zone, err := s.store.GetZone(ctx, s.db.Pool, zoneID)
	if err != nil {
		return err
	}
	if err := s.setState(ctx, zone, types.ZoneStateCordoning, ""); err != nil {
		return err
	}
	return s.run(ctx, zone, actor, DecommissionOrder, decommissionSteps)
}

// GetZone returns one zone with its steps.
func (s *Service) GetZone(ctx context.Context, id string) (*types.TenantZone, map[string]*types.TenantZoneStep, error) {
	z, err := s.store.GetZone(ctx, s.db.Pool, id)
	if err != nil {
		return nil, nil, err
	}
	steps, err := s.store.ListSteps(ctx, s.db.Pool, id)
	if err != nil {
		return nil, nil, err
	}
	return z, steps, nil
}

// ListZones returns the zones owned by an org.
func (s *Service) ListZones(ctx context.Context, ownerOrgID string) ([]types.TenantZone, error) {
	return s.store.ListZones(ctx, s.db.Pool, ownerOrgID)
}

// stepState maps decommission steps to the zone state shown while running.
var stepState = map[string]types.TenantZoneState{
	types.ZoneStepInariWiring: types.ZoneStateWiring,
	types.ZoneStepCordon:      types.ZoneStateCordoning,
	types.ZoneStepDrain:       types.ZoneStateDraining,
}

// run executes one step chain, persisting each transition in a TX with
// audit + outbox, and settles the zone on completion/failure.
func (s *Service) run(ctx context.Context, zone *types.TenantZone, actor string, order []string, funcs map[string]StepFunc) error {
	steps, err := s.store.ListSteps(ctx, s.db.Pool, zone.ID)
	if err != nil {
		return err
	}
	rc := &RunContext{Zone: zone, Steps: steps, Actor: actor}
	onUpdate := func(ctx context.Context, rc *RunContext, st *types.TenantZoneStep) error {
		if st.Status == types.ZoneStepRunning {
			return nil // only persist settled transitions
		}
		if st.Attempts > s.env.Config.MaxAttempts && st.Status == types.ZoneStepFailed {
			zone.State = types.ZoneStateManualIntervention
		} else if next, ok := stepState[st.Step]; ok && st.Status != types.ZoneStepFailed {
			zone.State = next
		}
		return s.db.WithTx(ctx, func(tx pgx.Tx) error {
			if err := s.store.UpsertStep(ctx, tx, st); err != nil {
				return err
			}
			if err := s.store.UpdateZone(ctx, tx, zone); err != nil {
				return err
			}
			if err := s.audit.Record(ctx, tx, &types.AuditEvent{
				OrgID: zone.OwnerOrgID, Actor: actor, Action: "tenant_zone.step_updated",
				ObjectType: "tenant_zone", ObjectID: zone.ID,
				Payload: json.RawMessage(fmt.Sprintf(`{"step":%q,"status":%q,"attempts":%d}`, st.Step, st.Status, st.Attempts)),
			}); err != nil {
				return err
			}
			return audit.AppendOutbox(ctx, tx, zone.OwnerOrgID, types.EventTenantZoneStepUpdated, types.TenantZonePayload{
				OrgID: zone.OwnerOrgID, ZoneID: zone.ID, Slug: zone.Slug,
				State: string(zone.State), Step: st.Step, StepStatus: st.Status,
			})
		})
	}
	complete, runErr := RunSteps(ctx, s.env, order, funcs, rc, onUpdate)
	switch {
	case runErr != nil && errors.Is(runErr, ErrPreflightDenied):
		zone.Error = runErr.Error()
		return s.settle(ctx, zone, types.ZoneStateFailed, types.EventTenantZoneFailed, actor, runErr)
	case runErr != nil:
		zone.Error = runErr.Error()
		if zone.State != types.ZoneStateManualIntervention {
			return s.settle(ctx, zone, types.ZoneStateFailed, types.EventTenantZoneFailed, actor, runErr)
		}
		return s.settle(ctx, zone, types.ZoneStateManualIntervention, types.EventTenantZoneFailed, actor, runErr)
	case complete:
		if order[0] == types.ZoneStepPreflight {
			return s.settle(ctx, zone, types.ZoneStateActive, types.EventTenantZoneActive, actor, nil)
		}
		return s.settle(ctx, zone, types.ZoneStateClosed, types.EventTenantZoneClosed, actor, nil)
	default:
		return nil // waiting on an async operation; the reconcile loop re-enters
	}
}

// settle writes the terminal zone state with the archived audit event.
func (s *Service) settle(ctx context.Context, zone *types.TenantZone, state types.TenantZoneState, event string, actor string, cause error) error {
	zone.State = state
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpdateZone(ctx, tx, zone); err != nil {
			return err
		}
		ev := &types.AuditEvent{
			OrgID: zone.OwnerOrgID, Actor: actor, Action: event,
			ObjectType: "tenant_zone", ObjectID: zone.ID,
		}
		if cause != nil {
			ev.Payload = json.RawMessage(fmt.Sprintf(`{"error":%q}`, cause.Error()))
		}
		if err := s.audit.Record(ctx, tx, ev); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, zone.OwnerOrgID, event, types.TenantZonePayload{
			OrgID: zone.OwnerOrgID, ZoneOrgID: zone.OrgID, ZoneID: zone.ID, Slug: zone.Slug, State: string(state),
		})
	})
}

func (s *Service) setState(ctx context.Context, zone *types.TenantZone, state types.TenantZoneState, errMsg string) error {
	zone.State = state
	zone.Error = errMsg
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return s.store.UpdateZone(ctx, tx, zone)
	})
}

// RunReconcileLoop resumes all in-progress zones on an interval — the
// crash-recovery and async-poll engine (§10). Runs until ctx is cancelled.
func (s *Service) RunReconcileLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		s.reconcileOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *Service) reconcileOnce(ctx context.Context) {
	zones, err := s.store.ListResumable(ctx, s.db.Pool)
	if err != nil {
		s.log.Warn("tzf: reconcile list failed", "error", err)
		return
	}
	for i := range zones {
		zone := &zones[i]
		if err := s.ResumeZone(ctx, zone.ID, "system:tenantzonefactory"); err != nil && ctx.Err() == nil {
			s.log.Warn("tzf: reconcile zone failed", "zone", zone.ID, "error", err)
		}
	}
}
