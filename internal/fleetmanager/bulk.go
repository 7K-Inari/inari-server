// Bulk fleet operations (plan §5.11): label queries across the fleet, bulk
// approval decisions, and bulk policy/catalog assignment. Every item is
// authorized and audited individually; failures are reported per item, never
// silently dropped.
package fleetmanager

import (
	"context"
	"fmt"

	"github.com/7K-Inari/inari-server/internal/types"
)

// ApprovalDecider decides one approval (approvals.Service seam).
type ApprovalDecider interface {
	Decide(ctx context.Context, orgID, approvalID, approver string, approve bool, reason string) (*types.ApprovalRequest, error)
}

// PolicyAssigner assigns a policy pack to a target (policyservice.Service).
type PolicyAssigner interface {
	Assign(ctx context.Context, actor, orgID, packID, targetType, targetID string) (*types.PolicyAssignment, error)
}

// CatalogPinner pins a tenant to a catalog item version (catalog.Service).
type CatalogPinner interface {
	SetPin(ctx context.Context, actor, orgID, itemID, version string) error
}

// WithBulkSeams wires the cross-module seams used by bulk operations.
func (s *Service) WithBulkSeams(decider ApprovalDecider, assigner PolicyAssigner, pinner CatalogPinner) *Service {
	s.decider, s.assigner, s.pinner = decider, assigner, pinner
	return s
}

// QueryClusters returns the org's clusters matching a label selector —
// the fleet-wide label query.
func (s *Service) QueryClusters(ctx context.Context, orgID string, selector map[string]string) ([]types.Cluster, error) {
	return s.ResolveClusters(ctx, orgID, selector)
}

// BulkItemResult is the per-item outcome of a bulk operation.
type BulkItemResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// BulkDecideApprovals approves/rejects a set of pending approvals. Each
// decision keeps its own audit + outbox trail via the Approvals module.
func (s *Service) BulkDecideApprovals(ctx context.Context, orgID, approver string, approvalIDs []string, approve bool, reason string) ([]BulkItemResult, error) {
	if s.decider == nil {
		return nil, fmt.Errorf("fleetmanager: approvals seam not wired")
	}
	if len(approvalIDs) == 0 {
		return nil, fmt.Errorf("%w: approvalIds is required", ErrInvalidInput)
	}
	out := make([]BulkItemResult, 0, len(approvalIDs))
	for _, id := range approvalIDs {
		_, err := s.decider.Decide(ctx, orgID, id, approver, approve, reason)
		res := BulkItemResult{ID: id, OK: err == nil}
		if err != nil {
			res.Error = err.Error()
		}
		out = append(out, res)
	}
	return out, nil
}

// BulkAssignPolicy assigns one pack to many ClusterSets. Per-item failures
// (e.g. a deleted set) are reported without aborting the batch.
func (s *Service) BulkAssignPolicy(ctx context.Context, actor, orgID, packID string, clusterSetIDs []string) ([]BulkItemResult, error) {
	if s.assigner == nil {
		return nil, fmt.Errorf("fleetmanager: policy seam not wired")
	}
	if len(clusterSetIDs) == 0 {
		return nil, fmt.Errorf("%w: clusterSetIds is required", ErrInvalidInput)
	}
	out := make([]BulkItemResult, 0, len(clusterSetIDs))
	for _, setID := range clusterSetIDs {
		_, err := s.assigner.Assign(ctx, actor, orgID, packID, types.PolicyTargetClusterSet, setID)
		res := BulkItemResult{ID: setID, OK: err == nil}
		if err != nil {
			res.Error = err.Error()
		}
		out = append(out, res)
	}
	return out, nil
}

// BulkPinCatalog pins many catalog items to a version for the tenant.
func (s *Service) BulkPinCatalog(ctx context.Context, actor, orgID string, itemIDs []string, version string) ([]BulkItemResult, error) {
	if s.pinner == nil {
		return nil, fmt.Errorf("fleetmanager: catalog seam not wired")
	}
	if len(itemIDs) == 0 || version == "" {
		return nil, fmt.Errorf("%w: itemIds and version are required", ErrInvalidInput)
	}
	out := make([]BulkItemResult, 0, len(itemIDs))
	for _, itemID := range itemIDs {
		err := s.pinner.SetPin(ctx, actor, orgID, itemID, version)
		res := BulkItemResult{ID: itemID, OK: err == nil}
		if err != nil {
			res.Error = err.Error()
		}
		out = append(out, res)
	}
	return out, nil
}
