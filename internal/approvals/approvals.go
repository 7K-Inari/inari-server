// Package approvals implements the approval workflow engine for catalog
// actions (plan §5.2). Policies: auto, peer (any org member except the
// requester), platform-admin (org-admin or platform-engineer). Requests
// carry the full deploy context so an approved request can be resumed by
// the orchestrator without the caller re-issuing the deploy; pending
// requests expire (default 7 days) and can be cancelled by the requester.
package approvals

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// ErrNotRequester is returned when someone other than the requester tries
// to cancel a request.
var ErrNotRequester = errors.New("approvals: only the requester can cancel")

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

const approvalCols = `id, org_id, COALESCE(item_id, ''), version, cluster_id, spec, requester, approver, state, reason,
	name, namespace, owner_team, channel, instance_id, action, created_at, decided_at, expires_at, cancelled_by`

func scanApproval(row interface{ Scan(...any) error }) (*types.ApprovalRequest, error) {
	var r types.ApprovalRequest
	err := row.Scan(&r.ID, &r.OrgID, &r.ItemID, &r.Version, &r.ClusterID,
		&r.Spec, &r.Requester, &r.Approver, &r.State, &r.Reason,
		&r.Name, &r.Namespace, &r.OwnerTeam, &r.Channel, &r.InstanceID, &r.Action,
		&r.CreatedAt, &r.DecidedAt, &r.ExpiresAt, &r.CancelledBy)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) create(ctx context.Context, q db.Querier, req *types.ApprovalRequest) error {
	const sql = `INSERT INTO approval_requests (org_id, item_id, version, cluster_id, spec, requester,
	             name, namespace, owner_team, channel, instance_id, expires_at)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id, state, created_at`
	return q.QueryRow(ctx, sql, req.OrgID, req.ItemID, req.Version, req.ClusterID, req.Spec, req.Requester,
		req.Name, req.Namespace, req.OwnerTeam, req.Channel, req.InstanceID, req.ExpiresAt).
		Scan(&req.ID, &req.State, &req.CreatedAt)
}

// createLifecycle persists a lifecycle approval request (no catalog item).
func (s *Store) createLifecycle(ctx context.Context, q db.Querier, req *types.ApprovalRequest) error {
	const sql = `INSERT INTO approval_requests (org_id, item_id, version, cluster_id, spec, requester,
	             action, expires_at)
	             VALUES ($1,NULL,'','',$2,$3,$4,$5) RETURNING id, state, created_at`
	return q.QueryRow(ctx, sql, req.OrgID, req.Spec, req.Requester, req.Action, req.ExpiresAt).
		Scan(&req.ID, &req.State, &req.CreatedAt)
}

func (s *Store) get(ctx context.Context, q db.Querier, id string) (*types.ApprovalRequest, error) {
	const sql = `SELECT ` + approvalCols + ` FROM approval_requests WHERE id = $1`
	r, err := scanApproval(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func (s *Store) list(ctx context.Context, q db.Querier, orgID, state, requester string) ([]types.ApprovalRequest, error) {
	sql := `SELECT ` + approvalCols + ` FROM approval_requests WHERE org_id = $1`
	args := []any{orgID}
	if state != "" {
		args = append(args, state)
		sql += fmt.Sprintf(` AND state = $%d`, len(args))
	}
	if requester != "" {
		args = append(args, requester)
		sql += fmt.Sprintf(` AND requester = $%d`, len(args))
	}
	sql += ` ORDER BY created_at DESC`
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.ApprovalRequest
	for rows.Next() {
		r, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// listExpired returns pending requests past their expiry.
func (s *Store) listExpired(ctx context.Context, q db.Querier, now time.Time) ([]types.ApprovalRequest, error) {
	const sql = `SELECT ` + approvalCols + ` FROM approval_requests
	             WHERE state = 'pending' AND expires_at IS NOT NULL AND expires_at <= $1`
	rows, err := q.Query(ctx, sql, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.ApprovalRequest
	for rows.Next() {
		r, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
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
	ttl   time.Duration
	now   func() time.Time
}

func NewService(d *db.DB, store *Store, auditStore *audit.Store, roles RoleResolver, items ItemResolver) *Service {
	return &Service{db: d, store: store, audit: auditStore, roles: roles, items: items, ttl: DefaultTTL, now: time.Now}
}

// DefaultTTL is how long a pending request waits for a decision.
const DefaultTTL = 7 * 24 * time.Hour

// WithTTL overrides the pending-request expiry (tests).
func (s *Service) WithTTL(d time.Duration) *Service { s.ttl = d; return s }

// GateResult reports whether a deploy may proceed immediately.
type GateResult struct {
	Approved   bool
	ApprovalID string // set when a request was created (pending)
}

// GateInput is one catalog action to gate. Name/Namespace/OwnerTeam/Channel
// carry the deploy context for post-approval resume; InstanceID is set when
// gating an upgrade of an existing instance.
type GateInput struct {
	OrgID      string
	Item       *types.CatalogItem
	Version    string
	ClusterID  string
	Spec       []byte
	Requester  string
	Name       string
	Namespace  string
	OwnerTeam  string
	Channel    string
	InstanceID string
}

// Gate evaluates the item's approval policy. auto → approved; otherwise an
// approval request is persisted and the deploy waits for Decide.
func (s *Service) Gate(ctx context.Context, in GateInput) (*GateResult, error) {
	if policyFor(in.Item) == types.ApprovalPolicyAuto {
		return &GateResult{Approved: true}, nil
	}
	expires := s.now().Add(s.ttl)
	req := &types.ApprovalRequest{
		OrgID: in.OrgID, ItemID: in.Item.ID, Version: in.Version, ClusterID: in.ClusterID,
		Spec: in.Spec, Requester: in.Requester, Name: in.Name, Namespace: in.Namespace,
		OwnerTeam: in.OwnerTeam, Channel: in.Channel, InstanceID: in.InstanceID,
		ExpiresAt: &expires,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.create(ctx, tx, req); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: in.OrgID, Actor: in.Requester, Action: "approval.requested",
			ObjectType: "approval_request", ObjectID: req.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, in.OrgID, types.EventApprovalRequested, types.ApprovalPayload{
			OrgID: in.OrgID, ApprovalID: req.ID, ItemID: in.Item.ID, State: types.ApprovalStatePending,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("approvals: gate: %w", err)
	}
	return &GateResult{Approved: false, ApprovalID: req.ID}, nil
}

// Get returns one approval request scoped to the org (404 on mismatch).
func (s *Service) Get(ctx context.Context, orgID, approvalID string) (*types.ApprovalRequest, error) {
	req, err := s.store.get(ctx, s.db.Pool, approvalID)
	if err != nil {
		return nil, err
	}
	if req.OrgID != orgID {
		return nil, ErrNotFound
	}
	return req, nil
}

// List returns approval requests for an org, optionally filtered by state
// and/or requester ("me" inbox filter passes the caller's actor string).
func (s *Service) List(ctx context.Context, orgID, state, requester string) ([]types.ApprovalRequest, error) {
	return s.store.list(ctx, s.db.Pool, orgID, state, requester)
}

// Cancel lets the requester withdraw a pending request. Emits audit +
// outbox (EventApprovalCancelled) so gated deploys never resume.
func (s *Service) Cancel(ctx context.Context, orgID, approvalID, actor string) (*types.ApprovalRequest, error) {
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
	if !sameActor(req.Requester, actor) {
		return nil, ErrNotRequester
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		const sql = `UPDATE approval_requests SET state = $2, cancelled_by = $3, decided_at = $4
		             WHERE id = $1 AND state = $5`
		tag, err := tx.Exec(ctx, sql, approvalID, types.ApprovalStateCancelled, actor, s.now(), types.ApprovalStatePending)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrAlreadyDecided
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: req.OrgID, Actor: actor, Action: "approval.cancelled",
			ObjectType: "approval_request", ObjectID: approvalID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, req.OrgID, types.EventApprovalCancelled, types.ApprovalPayload{
			OrgID: req.OrgID, ApprovalID: approvalID, ItemID: req.ItemID, State: types.ApprovalStateCancelled,
		})
	})
	if err != nil {
		return nil, err
	}
	req.State = types.ApprovalStateCancelled
	return req, nil
}

// ExpireSweep marks pending requests past their expiry as expired, emitting
// audit + outbox per request. Returns the number expired. Runs on a ticker
// from main (see RunExpiryLoop).
func (s *Service) ExpireSweep(ctx context.Context) (int, error) {
	expired, err := s.store.listExpired(ctx, s.db.Pool, s.now())
	if err != nil {
		return 0, err
	}
	for i := range expired {
		req := &expired[i]
		err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
			const sql = `UPDATE approval_requests SET state = $2, decided_at = $3
			             WHERE id = $1 AND state = $4`
			tag, err := tx.Exec(ctx, sql, req.ID, types.ApprovalStateExpired, s.now(), types.ApprovalStatePending)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return nil // concurrently decided — not an error
			}
			if err := s.audit.Record(ctx, tx, &types.AuditEvent{
				OrgID: req.OrgID, Actor: "system:approvals", Action: "approval.expired",
				ObjectType: "approval_request", ObjectID: req.ID,
			}); err != nil {
				return err
			}
			return audit.AppendOutbox(ctx, tx, req.OrgID, types.EventApprovalExpired, types.ApprovalPayload{
				OrgID: req.OrgID, ApprovalID: req.ID, ItemID: req.ItemID, State: types.ApprovalStateExpired,
			})
		})
		if err != nil {
			return 0, err
		}
	}
	return len(expired), nil
}

// RunExpiryLoop runs ExpireSweep on an interval until ctx is cancelled.
func (s *Service) RunExpiryLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if _, err := s.ExpireSweep(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("approval expiry sweep failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
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
	role, err := s.roles.RoleOf(ctx, req.OrgID, approver)
	if err != nil {
		return nil, err
	}
	if req.Action != "" {
		// Lifecycle approval: platform-admin policy, no catalog item.
		if err := checkLifecycleApprover(req, approver, role); err != nil {
			return nil, err
		}
	} else {
		item, err := s.items.GetItemByID(ctx, req.ItemID)
		if err != nil {
			return nil, err
		}
		if err := checkApprover(item, req, approver, role); err != nil {
			return nil, err
		}
	}
	state := types.ApprovalStateRejected
	if approve {
		state = types.ApprovalStateApproved
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		const sql = `UPDATE approval_requests SET state = $2, approver = $3, reason = $4, decided_at = $5
		             WHERE id = $1 AND state = $6`
		tag, err := tx.Exec(ctx, sql, approvalID, state, approver, reason, s.now(), types.ApprovalStatePending)
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
