// Generic lifecycle approval actions (plan §5.11/§5.12): control-plane
// operations that are not catalog deploys (tenant zone vend/decommission)
// gate through the same approval workflow — always platform-admin policy —
// and resume via the approval.decided outbox event like gated deploys.
package approvals

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ValidLifecycleAction reports whether action is a known lifecycle approval
// action.
func ValidLifecycleAction(action string) bool {
	switch action {
	case types.ApprovalActionTenantZoneVend, types.ApprovalActionTenantZoneDecommission,
		types.ApprovalActionRolloutStageGate, types.ApprovalActionTenantDecommission:
		return true
	}
	return false
}

// authorizeLifecycleApprover enforces the platform-admin policy on lifecycle
// decisions. A tenant freeze sweeps the org's FGA tuples before its lifecycle
// approval is decided (ADR-0006), so authorization accepts a platform
// org_creator (FGA, platform:inari) OR a DB-backed org-admin/platform-engineer
// role (RoleOf reads org_memberships, which survives the tuple sweep). The
// requester may never decide their own request.
func (s *Service) authorizeLifecycleApprover(ctx context.Context, req *types.ApprovalRequest, approver string) error {
	if sameActor(req.Requester, approver) {
		return ErrSelfApproval
	}
	if s.platform != nil {
		ok, err := s.platform.Check(ctx, authz.UserObject(approver), authz.RelationOrgCreator, authz.ObjectPlatform)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	if s.roles == nil {
		return ErrApproverRole
	}
	role, err := s.roles.RoleOf(ctx, req.OrgID, approver)
	if err != nil {
		return err
	}
	if role != types.RoleOrgAdmin && role != types.RolePlatformEngineer {
		return ErrApproverRole
	}
	return nil
}

// LifecycleApprovalInput is one lifecycle operation to gate. Context is the
// JSON payload the resume handler needs to re-enter the operation after
// approval (e.g. the zone ID and request parameters).
type LifecycleApprovalInput struct {
	OrgID     string
	Action    string
	Requester string
	Context   json.RawMessage
}

// RequestLifecycleApproval persists a pending platform-admin approval for a
// lifecycle action and emits approval.requested. The operation resumes via
// the approval.decided outbox event.
func (s *Service) RequestLifecycleApproval(ctx context.Context, in LifecycleApprovalInput) (*types.ApprovalRequest, error) {
	if !ValidLifecycleAction(in.Action) {
		return nil, fmt.Errorf("approvals: unknown lifecycle action %q", in.Action)
	}
	expires := s.now().Add(s.ttl)
	req := &types.ApprovalRequest{
		OrgID: in.OrgID, Action: in.Action, Spec: in.Context,
		Requester: in.Requester, ExpiresAt: &expires,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.createLifecycle(ctx, tx, req); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: in.OrgID, Actor: in.Requester, Action: "approval.requested",
			ObjectType: "approval_request", ObjectID: req.ID,
			Payload: json.RawMessage(fmt.Sprintf(`{"action":%q}`, in.Action)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, in.OrgID, types.EventApprovalRequested, types.ApprovalPayload{
			OrgID: in.OrgID, ApprovalID: req.ID, State: types.ApprovalStatePending,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("approvals: lifecycle gate: %w", err)
	}
	return req, nil
}
