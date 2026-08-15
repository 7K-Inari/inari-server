// Package approvals implements basic per-item approval gating for deploy
// requests (plan §5.2; full workflow polish lands in M3). Policies: auto,
// peer (any org member except the requester), platform-admin (org-admin or
// platform-engineer).
package approvals

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrNotFound is returned for unknown approval requests.
var ErrNotFound = errors.New("approvals: request not found")

// ErrAlreadyDecided is returned when deciding a settled request.
var ErrAlreadyDecided = errors.New("approvals: request already decided")

// ErrSelfApproval is returned when the requester tries to approve their own
// request under a peer policy.
var ErrSelfApproval = errors.New("approvals: requester cannot self-approve")

// ErrApproverRole is returned when the approver lacks the required role.
var ErrApproverRole = errors.New("approvals: approver lacks required role")

func policyFor(item *types.CatalogItem) types.ApprovalPolicy {
	if item.ApprovalPolicy == "" {
		return types.ApprovalPolicyAuto
	}
	return item.ApprovalPolicy
}

// checkApprover validates that approver (with their org role) may decide req
// under the item's policy.
func checkApprover(item *types.CatalogItem, req *types.ApprovalRequest, approver string, role types.Role) error {
	switch policyFor(item) {
	case types.ApprovalPolicyPeer:
		// The requester is stored with the actor prefix ("user:<subject>")
		// while approvers arrive as bare subjects — normalize both sides.
		if sameActor(req.Requester, approver) {
			return ErrSelfApproval
		}
	case types.ApprovalPolicyPlatformAdmin:
		if role != types.RoleOrgAdmin && role != types.RolePlatformEngineer {
			return ErrApproverRole
		}
	}
	return nil
}

// sameActor reports whether two actor strings name the same subject,
// tolerating an optional "user:" prefix on either side.
func sameActor(a, b string) bool {
	return strings.TrimPrefix(a, "user:") == strings.TrimPrefix(b, "user:")
}

// Store persists approval requests.
type Store struct {
	db *db.DB
}

func NewStore(d *db.DB) *Store { return &Store{db: d} }

func (s *Store) create(ctx context.Context, q db.Querier, req *types.ApprovalRequest) error {
	const sql = `INSERT INTO approval_requests (org_id, item_id, version, cluster_id, spec, requester)
	             VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, state, created_at`
	return q.QueryRow(ctx, sql, req.OrgID, req.ItemID, req.Version, req.ClusterID, req.Spec, req.Requester).
		Scan(&req.ID, &req.State, &req.CreatedAt)
}

func (s *Store) get(ctx context.Context, q db.Querier, id string) (*types.ApprovalRequest, error) {
	const sql = `SELECT id, org_id, item_id, version, cluster_id, spec, requester, approver, state, reason, created_at, decided_at
	             FROM approval_requests WHERE id = $1`
	var r types.ApprovalRequest
	err := q.QueryRow(ctx, sql, id).Scan(&r.ID, &r.OrgID, &r.ItemID, &r.Version, &r.ClusterID,
		&r.Spec, &r.Requester, &r.Approver, &r.State, &r.Reason, &r.CreatedAt, &r.DecidedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &r, err
}

func (s *Store) list(ctx context.Context, q db.Querier, orgID, state string) ([]types.ApprovalRequest, error) {
	sql := `SELECT id, org_id, item_id, version, cluster_id, spec, requester, approver, state, reason, created_at, decided_at
	        FROM approval_requests WHERE org_id = $1`
	args := []any{orgID}
	if state != "" {
		sql += ` AND state = $2`
		args = append(args, state)
	}
	sql += ` ORDER BY created_at DESC`
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.ApprovalRequest
	for rows.Next() {
		var r types.ApprovalRequest
		if err := rows.Scan(&r.ID, &r.OrgID, &r.ItemID, &r.Version, &r.ClusterID,
			&r.Spec, &r.Requester, &r.Approver, &r.State, &r.Reason, &r.CreatedAt, &r.DecidedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RoleResolver resolves a user's highest org role (tenancy.Service seam).
type RoleResolver interface {
	RoleOf(ctx context.Context, orgID, userID string) (types.Role, error)
}

// ItemResolver loads a catalog item (catalog.Service seam).
type ItemResolver interface {
	GetItemByID(ctx context.Context, itemID string) (*types.CatalogItem, error)
}

// Service gates deploy requests on the item's approval policy.
type Service struct {
	db    *db.DB
	store *Store
	audit *audit.Store
	roles RoleResolver
	items ItemResolver
}

func NewService(d *db.DB, store *Store, auditStore *audit.Store, roles RoleResolver, items ItemResolver) *Service {
	return &Service{db: d, store: store, audit: auditStore, roles: roles, items: items}
}

// GateResult reports whether a deploy may proceed immediately.
type GateResult struct {
	Approved   bool
	ApprovalID string // set when a request was created (pending)
}

// Gate evaluates the item's approval policy. auto → approved; otherwise an
// approval request is persisted and the deploy waits for Decide.
func (s *Service) Gate(ctx context.Context, orgID string, item *types.CatalogItem, version, clusterID string, spec []byte, requester string) (*GateResult, error) {
	if policyFor(item) == types.ApprovalPolicyAuto {
		return &GateResult{Approved: true}, nil
	}
	req := &types.ApprovalRequest{
		OrgID: orgID, ItemID: item.ID, Version: version, ClusterID: clusterID,
		Spec: spec, Requester: requester,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.create(ctx, tx, req); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: requester, Action: "approval.requested",
			ObjectType: "approval_request", ObjectID: req.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventApprovalRequested, types.ApprovalPayload{
			OrgID: orgID, ApprovalID: req.ID, ItemID: item.ID, State: types.ApprovalStatePending,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("approvals: gate: %w", err)
	}
	return &GateResult{Approved: false, ApprovalID: req.ID}, nil
}

// IsApproved reports whether the given approval request is approved.
func (s *Service) IsApproved(ctx context.Context, approvalID string) (bool, error) {
	req, err := s.store.get(ctx, s.db.Pool, approvalID)
	if err != nil {
		return false, err
	}
	return req.State == types.ApprovalStateApproved, nil
}

// List returns approval requests for an org, optionally filtered by state.
func (s *Service) List(ctx context.Context, orgID, state string) ([]types.ApprovalRequest, error) {
	return s.store.list(ctx, s.db.Pool, orgID, state)
}

// Decide approves or rejects a pending request, enforcing the item's policy
// on the approver. orgID scopes the request to the caller's tenant. Emits
// audit + outbox.
func (s *Service) Decide(ctx context.Context, orgID, approvalID, approver string, approve bool, reason string) (*types.ApprovalRequest, error) {
	req, err := s.store.get(ctx, s.db.Pool, approvalID)
	if err != nil {
		return nil, err
	}
	if req.OrgID != orgID {
		return nil, ErrNotFound
	}
	if req.State != types.ApprovalStatePending {
		return nil, ErrAlreadyDecided
	}
	item, err := s.items.GetItemByID(ctx, req.ItemID)
	if err != nil {
		return nil, err
	}
	role, err := s.roles.RoleOf(ctx, req.OrgID, approver)
	if err != nil {
		return nil, err
	}
	if err := checkApprover(item, req, approver, role); err != nil {
		return nil, err
	}
	state := types.ApprovalStateRejected
	if approve {
		state = types.ApprovalStateApproved
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		const sql = `UPDATE approval_requests SET state = $2, approver = $3, reason = $4, decided_at = $5
		             WHERE id = $1 AND state = $6`
		tag, err := tx.Exec(ctx, sql, approvalID, state, approver, reason, time.Now(), types.ApprovalStatePending)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrAlreadyDecided
		}
		req.State = state
		req.Approver = approver
		req.Reason = reason
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: req.OrgID, Actor: approver, Action: "approval." + state,
			ObjectType: "approval_request", ObjectID: approvalID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, req.OrgID, types.EventApprovalDecided, types.ApprovalPayload{
			OrgID: req.OrgID, ApprovalID: approvalID, ItemID: req.ItemID, State: state,
		})
	})
	if err != nil {
		return nil, err
	}
	return req, nil
}
