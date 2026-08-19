// Approval-decision resume: consumes approval.decided outbox events and, on
// approval, resumes the gated deploy/upgrade with the stored request
// context (plan §5.2 Approvals ↔ Orchestrator coupling, M3). The resumed
// apply runs as control-plane automation impersonating the tenant-scoped
// virtual user, so the audit trail records both identities (§5.4).
package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/7K-Inari/inari-server/internal/impersonation"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ApprovalLoader loads a decided approval request (approvals.Service seam).
type ApprovalLoader interface {
	Get(ctx context.Context, orgID, approvalID string) (*types.ApprovalRequest, error)
}

// ResumeHandler implements audit.Handler for EventApprovalDecided. On
// "approved" it re-enters the deploy path with the request context stored
// at gate time; rejected requests are terminal (the requester is notified
// via the Notifications module).
type ResumeHandler struct {
	svc       *Service
	approvals ApprovalLoader
	log       *slog.Logger
}

func NewResumeHandler(svc *Service, approvals ApprovalLoader, log *slog.Logger) *ResumeHandler {
	if log == nil {
		log = slog.Default()
	}
	return &ResumeHandler{svc: svc, approvals: approvals, log: log}
}

func (h *ResumeHandler) EventTypes() []string { return []string{types.EventApprovalDecided} }

func (h *ResumeHandler) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	var p types.ApprovalPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return fmt.Errorf("orchestrator: resume: payload: %w", err)
	}
	if p.State != types.ApprovalStateApproved {
		return nil
	}
	req, err := h.approvals.Get(ctx, p.OrgID, p.ApprovalID)
	if err != nil {
		return fmt.Errorf("orchestrator: resume: load approval %s: %w", p.ApprovalID, err)
	}
	// Double-audit: the real actor is the approvals automation; the
	// impersonated identity is the tenant-scoped virtual user (§5.4).
	ctx = impersonation.WithImpersonator(ctx, impersonation.VirtualUser(req.OrgID))
	deploy := DeployRequest{
		OrgID: req.OrgID, ClusterID: req.ClusterID, ItemID: req.ItemID,
		Version: req.Version, Channel: req.Channel, Name: req.Name,
		Namespace: req.Namespace, OwnerTeam: req.OwnerTeam,
		Spec: req.Spec, Requester: impersonation.SystemActor("approvals"),
	}
	item, err := h.svc.catalog.GetItemByID(ctx, req.ItemID)
	if err != nil {
		return fmt.Errorf("orchestrator: resume: item %s: %w", req.ItemID, err)
	}
	// Re-run request-time policy: a policy created or tightened between the
	// approval request and the decision must still gate the resumed deploy.
	cluster, err := h.svc.clusters.GetCluster(ctx, req.ClusterID)
	if err != nil {
		return fmt.Errorf("orchestrator: resume: cluster %s: %w", req.ClusterID, err)
	}
	if err := h.svc.preFlight(ctx, PolicyInput{
		OrgID: req.OrgID, ItemID: req.ItemID, Version: req.Version,
		ClusterID: req.ClusterID, Spec: req.Spec, Requester: deploy.Requester,
		ClusterLabels: cluster.Labels, ClusterDistribution: cluster.Distribution,
	}); err != nil {
		var pv *PolicyViolationError
		if errors.As(err, &pv) {
			// Terminal block: do not retry the outbox event forever.
			h.log.Warn("orchestrator: resumed deploy blocked by policy",
				"approval", p.ApprovalID, "violations", pv.Decision.Violations)
			return nil
		}
		return fmt.Errorf("orchestrator: resume: preflight: %w", err)
	}
	var res *DeployResult
	var applyErr error
	if req.InstanceID != "" {
		existing, err := h.svc.instances.Get(ctx, h.svc.db.Pool, req.InstanceID)
		if err != nil {
			return fmt.Errorf("orchestrator: resume: instance %s: %w", req.InstanceID, err)
		}
		res, applyErr = h.svc.apply(ctx, deploy, item, req.Version, existing)
	} else {
		res, applyErr = h.svc.apply(ctx, deploy, item, req.Version, nil)
	}
	if applyErr != nil {
		if errors.Is(applyErr, ErrInstanceExists) {
			// Deployed meanwhile (e.g. duplicate delivery) — idempotent no-op.
			h.log.Info("orchestrator: resume skipped, instance exists", "approval", p.ApprovalID)
			return nil
		}
		return fmt.Errorf("orchestrator: resume approval %s: %w", p.ApprovalID, applyErr)
	}
	h.log.Info("orchestrator: approval-gated deploy resumed",
		"approval", p.ApprovalID, "instance", res.InstanceID, "status", res.Status)
	return nil
}
