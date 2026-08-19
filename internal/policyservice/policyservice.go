// Package policyservice implements the Policy Service module (plan §5.11):
// one policy model evaluated at request time (pre-flight, target=request)
// and at render time (manifest checks, target=render), policy pack
// distribution to ClusterSets/tenants/clusters, and time-boxed,
// approval-gated exemptions.
//
// Rego contract: every policy source is package `inari.policy` and exposes
// two partial sets evaluated via the query `data.inari.policy`:
//
//	deny contains {"rule": ..., "reason": ..., "remediation": ...} — blocking
//	warn contains {"rule": ..., "reason": ..., "remediation": ...} — warnings
//
// Pre-flight input: {"org","item","version","cluster":{"id","labels",
// "distribution"},"spec","requester"}. Render input: {"org","manifests"}.
//
// Exemption approval gating for v1 lives in the HTTP layer (DecideExemption
// requires the platform_engineer relation); integration with the Approvals
// engine is a follow-up.
package policyservice

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

var (
	ErrPolicyNotFound      = errors.New("policy not found")
	ErrPackNotFound        = errors.New("policy pack not found")
	ErrClusterSetNotFound  = errors.New("cluster set not found")
	ErrExemptionNotFound   = errors.New("exemption not found")
	ErrAssignmentNotFound  = errors.New("policy assignment not found")
	ErrAssignmentExists    = errors.New("policy pack already assigned to target")
	ErrExemptionNotPending = errors.New("exemption is not pending")
	ErrInvalidInput        = errors.New("policyservice: invalid input")
)

// MaxExemptionDuration bounds exemption lifetime (§5.11).
const MaxExemptionDuration = 90 * 24 * time.Hour

// ClusterLister is the cluster registry seam (satisfied by
// clusterregistry.Service).
type ClusterLister interface {
	ListClusters(ctx context.Context, orgID string) ([]types.Cluster, error)
	GetCluster(ctx context.Context, id string) (*types.Cluster, error)
}

// Queue is the agent command queue seam (agentgateway.Queue).
type Queue interface {
	Enqueue(ctx context.Context, cmd *types.AgentCommand) error
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}

// Store is the PostgreSQL projection of policy service state.
type Store struct{}

func NewStore() *Store { return &Store{} }

const policyCols = `id, org_id, name, target, engine, source, enabled, version, created_at, updated_at`

func scanPolicy(row interface{ Scan(...any) error }) (*types.Policy, error) {
	var p types.Policy
	var orgID *string
	err := row.Scan(&p.ID, &orgID, &p.Name, &p.Target, &p.Engine, &p.Source, &p.Enabled,
		&p.Version, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if orgID != nil {
		p.OrgID = *orgID
	}
	return &p, nil
}

func (s *Store) CreatePolicy(ctx context.Context, q db.Querier, p *types.Policy) error {
	const sql = `INSERT INTO policies (id, org_id, name, target, engine, source, enabled)
	             VALUES ($1, NULLIF($2,''), $3, $4, $5, $6, $7) RETURNING ` + policyCols
	out, err := scanPolicy(q.QueryRow(ctx, sql, p.ID, p.OrgID, p.Name, p.Target, p.Engine, p.Source, p.Enabled))
	if err != nil {
		return err
	}
	*p = *out
	return nil
}

func (s *Store) GetPolicy(ctx context.Context, q db.Querier, id string) (*types.Policy, error) {
	const sql = `SELECT ` + policyCols + ` FROM policies WHERE id = $1`
	p, err := scanPolicy(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ListPolicies returns the org's policies plus platform-global rows
// (org_id IS NULL).
func (s *Store) ListPolicies(ctx context.Context, q db.Querier, orgID string) ([]types.Policy, error) {
	const sql = `SELECT ` + policyCols + ` FROM policies WHERE org_id = $1 OR org_id IS NULL ORDER BY created_at`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// UpdatePolicy replaces source/enabled and bumps the version.
func (s *Store) UpdatePolicy(ctx context.Context, q db.Querier, p *types.Policy) error {
	const sql = `UPDATE policies SET source = $2, enabled = $3, version = version + 1, updated_at = now()
	             WHERE id = $1 RETURNING ` + policyCols
	out, err := scanPolicy(q.QueryRow(ctx, sql, p.ID, p.Source, p.Enabled))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPolicyNotFound
	}
	if err != nil {
		return err
	}
	*p = *out
	return nil
}

func (s *Store) DeletePolicy(ctx context.Context, q db.Querier, id string) error {
	const sql = `DELETE FROM policies WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

const clusterSetCols = `id, org_id, name, label_selector, created_at`

func scanClusterSet(row interface{ Scan(...any) error }) (*types.ClusterSet, error) {
	var cs types.ClusterSet
	var selector []byte
	err := row.Scan(&cs.ID, &cs.OrgID, &cs.Name, &selector, &cs.CreatedAt)
	if err != nil {
		return nil, err
	}
	if len(selector) > 0 {
		if err := json.Unmarshal(selector, &cs.LabelSelector); err != nil {
			return nil, fmt.Errorf("policyservice: cluster set selector: %w", err)
		}
	}
	return &cs, nil
}

func (s *Store) CreateClusterSet(ctx context.Context, q db.Querier, cs *types.ClusterSet) error {
	sel, err := json.Marshal(cs.LabelSelector)
	if err != nil {
		return err
	}
	const sql = `INSERT INTO cluster_sets (id, org_id, name, label_selector) VALUES ($1,$2,$3,$4)
	             RETURNING ` + clusterSetCols
	out, err := scanClusterSet(q.QueryRow(ctx, sql, cs.ID, cs.OrgID, cs.Name, sel))
	if err != nil {
		return err
	}
	*cs = *out
	return nil
}

func (s *Store) GetClusterSet(ctx context.Context, q db.Querier, id string) (*types.ClusterSet, error) {
	const sql = `SELECT ` + clusterSetCols + ` FROM cluster_sets WHERE id = $1`
	cs, err := scanClusterSet(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClusterSetNotFound
	}
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func (s *Store) ListClusterSets(ctx context.Context, q db.Querier, orgID string) ([]types.ClusterSet, error) {
	const sql = `SELECT ` + clusterSetCols + ` FROM cluster_sets WHERE org_id = $1 ORDER BY created_at`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.ClusterSet
	for rows.Next() {
		cs, err := scanClusterSet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *cs)
	}
	return out, rows.Err()
}

func (s *Store) DeleteClusterSet(ctx context.Context, q db.Querier, id string) error {
	const sql = `DELETE FROM cluster_sets WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrClusterSetNotFound
	}
	return nil
}

const packCols = `id, org_id, name, engine, oci_ref, version, parameters, manifests, created_at`

func scanPack(row interface{ Scan(...any) error }) (*types.PolicyPack, error) {
	var p types.PolicyPack
	var orgID *string
	err := row.Scan(&p.ID, &orgID, &p.Name, &p.Engine, &p.OCIRef, &p.Version, &p.Parameters, &p.Manifests, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	if orgID != nil {
		p.OrgID = *orgID
	}
	return &p, nil
}

func (s *Store) CreatePolicyPack(ctx context.Context, q db.Querier, p *types.PolicyPack) error {
	const sql = `INSERT INTO policy_packs (id, org_id, name, engine, oci_ref, version, parameters, manifests)
	             VALUES ($1, NULLIF($2,''), $3, $4, $5, $6, $7, $8) RETURNING ` + packCols
	out, err := scanPack(q.QueryRow(ctx, sql, p.ID, p.OrgID, p.Name, p.Engine, p.OCIRef, p.Version, p.Parameters, p.Manifests))
	if err != nil {
		return err
	}
	*p = *out
	return nil
}

func (s *Store) GetPolicyPack(ctx context.Context, q db.Querier, id string) (*types.PolicyPack, error) {
	const sql = `SELECT ` + packCols + ` FROM policy_packs WHERE id = $1`
	p, err := scanPack(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPackNotFound
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ListPolicyPacks returns the org's packs plus platform-global rows.
func (s *Store) ListPolicyPacks(ctx context.Context, q db.Querier, orgID string) ([]types.PolicyPack, error) {
	const sql = `SELECT ` + packCols + ` FROM policy_packs WHERE org_id = $1 OR org_id IS NULL ORDER BY created_at`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.PolicyPack
	for rows.Next() {
		p, err := scanPack(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

const assignmentCols = `id, pack_id, target_type, target_id, state, created_at`

func (s *Store) CreateAssignment(ctx context.Context, q db.Querier, a *types.PolicyAssignment) error {
	const sql = `INSERT INTO policy_assignments (id, pack_id, target_type, target_id, state)
	             VALUES ($1,$2,$3,$4,'active') RETURNING ` + assignmentCols
	err := q.QueryRow(ctx, sql, a.ID, a.PackID, a.TargetType, a.TargetID).
		Scan(&a.ID, &a.PackID, &a.TargetType, &a.TargetID, &a.State, &a.CreatedAt)
	if isUniqueViolation(err) {
		return ErrAssignmentExists
	}
	return err
}

func (s *Store) ListAssignments(ctx context.Context, q db.Querier, packID string) ([]types.PolicyAssignment, error) {
	const sql = `SELECT ` + assignmentCols + ` FROM policy_assignments WHERE pack_id = $1 ORDER BY created_at`
	rows, err := q.Query(ctx, sql, packID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.PolicyAssignment
	for rows.Next() {
		var a types.PolicyAssignment
		if err := rows.Scan(&a.ID, &a.PackID, &a.TargetType, &a.TargetID, &a.State, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAssignment(ctx context.Context, q db.Querier, id string) error {
	const sql = `DELETE FROM policy_assignments WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAssignmentNotFound
	}
	return nil
}

const exemptionCols = `id, org_id, policy_id, scope, reason, state, expires_at, approved_by, created_by, created_at`

func scanExemption(row interface{ Scan(...any) error }) (*types.Exemption, error) {
	var e types.Exemption
	err := row.Scan(&e.ID, &e.OrgID, &e.PolicyID, &e.Scope, &e.Reason, &e.State,
		&e.ExpiresAt, &e.ApprovedBy, &e.CreatedBy, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *Store) CreateExemption(ctx context.Context, q db.Querier, e *types.Exemption) error {
	const sql = `INSERT INTO exemptions (id, org_id, policy_id, scope, reason, state, expires_at, created_by)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING ` + exemptionCols
	out, err := scanExemption(q.QueryRow(ctx, sql, e.ID, e.OrgID, e.PolicyID, e.Scope, e.Reason, e.State, e.ExpiresAt, e.CreatedBy))
	if err != nil {
		return err
	}
	*e = *out
	return nil
}

func (s *Store) GetExemption(ctx context.Context, q db.Querier, id string) (*types.Exemption, error) {
	const sql = `SELECT ` + exemptionCols + ` FROM exemptions WHERE id = $1`
	e, err := scanExemption(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrExemptionNotFound
	}
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (s *Store) ListExemptions(ctx context.Context, q db.Querier, orgID string) ([]types.Exemption, error) {
	const sql = `SELECT ` + exemptionCols + ` FROM exemptions WHERE org_id = $1 ORDER BY created_at`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Exemption
	for rows.Next() {
		e, err := scanExemption(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

func (s *Store) SetExemptionState(ctx context.Context, q db.Querier, id, state, approvedBy string) error {
	const sql = `UPDATE exemptions SET state = $2, approved_by = $3 WHERE id = $1 AND state = 'pending'`
	tag, err := q.Exec(ctx, sql, id, state, approvedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrExemptionNotPending
	}
	return nil
}

// ListValidExemptions returns approved, unexpired exemptions for one policy
// in one org.
func (s *Store) ListValidExemptions(ctx context.Context, q db.Querier, orgID, policyID string, now time.Time) ([]types.Exemption, error) {
	const sql = `SELECT ` + exemptionCols + ` FROM exemptions
	             WHERE org_id = $1 AND policy_id = $2 AND state = 'approved' AND expires_at > $3`
	rows, err := q.Query(ctx, sql, orgID, policyID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Exemption
	for rows.Next() {
		e, err := scanExemption(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// Service orchestrates the policy module: DB projection + audit + outbox in
// one TX, OPA evaluation via the Evaluator seam, distribution via Queue.
type Service struct {
	db       *db.DB
	store    *Store
	eval     Evaluator
	clusters ClusterLister
	queue    Queue
	audit    *audit.Store
	now      func() time.Time
}

func NewService(d *db.DB, store *Store, eval Evaluator, clusters ClusterLister, queue Queue, auditStore *audit.Store) *Service {
	return &Service{
		db: d, store: store, eval: eval, clusters: clusters, queue: queue,
		audit: auditStore, now: time.Now,
	}
}

func (s *Service) CreatePolicy(ctx context.Context, actor, orgID, name, target, engine, source string) (*types.Policy, error) {
	if target != types.PolicyTargetRequest && target != types.PolicyTargetRender {
		return nil, fmt.Errorf("%w: target must be request|render", ErrInvalidInput)
	}
	if engine != types.PolicyEngineRego {
		return nil, fmt.Errorf("%w: engine must be rego", ErrInvalidInput)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if err := s.eval.Compile(source); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	p := &types.Policy{
		ID: "policy:" + newUUID(), OrgID: orgID, Name: name,
		Target: target, Engine: engine, Source: source, Enabled: true,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreatePolicy(ctx, tx, p); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "policy.created", ObjectType: "policy", ObjectID: p.ID,
		})
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// GetPolicy returns one policy visible to the org (own or platform-global).
func (s *Service) GetPolicy(ctx context.Context, orgID, id string) (*types.Policy, error) {
	p, err := s.store.GetPolicy(ctx, s.db.Pool, id)
	if err != nil {
		return nil, err
	}
	if p.OrgID != "" && p.OrgID != orgID {
		return nil, ErrPolicyNotFound
	}
	return p, nil
}

func (s *Service) ListPolicies(ctx context.Context, orgID string) ([]types.Policy, error) {
	return s.store.ListPolicies(ctx, s.db.Pool, orgID)
}

func (s *Service) UpdatePolicy(ctx context.Context, actor, orgID, id, source string, enabled bool) (*types.Policy, error) {
	p, err := s.GetPolicy(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if p.OrgID == "" {
		return nil, fmt.Errorf("%w: platform-global policies are not editable by tenants", ErrInvalidInput)
	}
	if err := s.eval.Compile(source); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	p.Source = source
	p.Enabled = enabled
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpdatePolicy(ctx, tx, p); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "policy.updated", ObjectType: "policy", ObjectID: p.ID,
			Payload: json.RawMessage(fmt.Sprintf(`{"version":%d}`, p.Version)),
		})
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Service) DeletePolicy(ctx context.Context, actor, orgID, id string) error {
	p, err := s.GetPolicy(ctx, orgID, id)
	if err != nil {
		return err
	}
	if p.OrgID == "" {
		return fmt.Errorf("%w: platform-global policies are not deletable by tenants", ErrInvalidInput)
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.DeletePolicy(ctx, tx, id); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "policy.deleted", ObjectType: "policy", ObjectID: id,
		})
	})
}

// PreFlightInput is one request-time (pre-flight) evaluation input.
type PreFlightInput struct {
	OrgID               string
	ItemID              string
	Version             string
	ClusterID           string
	Spec                json.RawMessage
	Requester           string
	ClusterLabels       map[string]string
	ClusterDistribution string
}

// PreFlight evaluates all enabled request-target policies (org + global)
// against a deploy intent. Violations block unless covered by a valid
// (approved, unexpired) exemption.
func (s *Service) PreFlight(ctx context.Context, in PreFlightInput) (*types.PolicyDecision, error) {
	var spec any
	if len(in.Spec) > 0 {
		if err := json.Unmarshal(in.Spec, &spec); err != nil {
			return nil, fmt.Errorf("%w: spec must be valid JSON", ErrInvalidInput)
		}
	}
	input := map[string]any{
		"org":     in.OrgID,
		"item":    in.ItemID,
		"version": in.Version,
		"cluster": map[string]any{
			"id":           in.ClusterID,
			"labels":       in.ClusterLabels,
			"distribution": in.ClusterDistribution,
		},
		"spec":      spec,
		"requester": in.Requester,
	}
	return s.evaluate(ctx, in.OrgID, types.PolicyTargetRequest, input)
}

// RenderCheck evaluates all enabled render-target policies against rendered
// manifests. Violations block; warn rules surface as non-blocking warnings.
func (s *Service) RenderCheck(ctx context.Context, orgID string, manifests ...[]byte) (*types.PolicyDecision, error) {
	docs := make([]any, 0, len(manifests))
	for i, raw := range manifests {
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("%w: manifest %d must be valid JSON", ErrInvalidInput, i)
		}
		docs = append(docs, doc)
	}
	return s.evaluate(ctx, orgID, types.PolicyTargetRender, map[string]any{
		"org":       orgID,
		"manifests": docs,
	})
}

func (s *Service) evaluate(ctx context.Context, orgID, target string, input map[string]any) (*types.PolicyDecision, error) {
	policies, err := s.store.ListPolicies(ctx, s.db.Pool, orgID)
	if err != nil {
		return nil, err
	}
	decision := &types.PolicyDecision{Allow: true}
	now := s.now()
	for i := range policies {
		p := &policies[i]
		if !p.Enabled || p.Target != target {
			continue
		}
		denies, warns, err := s.eval.Eval(ctx, p, input)
		if err != nil {
			return nil, err
		}
		if len(denies) > 0 {
			// v1 exemption matching: any valid exemption for the policy
			// exempts all of its violations. Scope-aware matching is a
			// documented follow-up (§5.11).
			valid, err := s.store.ListValidExemptions(ctx, s.db.Pool, orgID, p.ID, now)
			if err != nil {
				return nil, err
			}
			for j := range denies {
				denies[j].Exempted = len(valid) > 0
				decision.Violations = append(decision.Violations, denies[j])
			}
		}
		decision.Warnings = append(decision.Warnings, warns...)
	}
	for _, v := range decision.Violations {
		if !v.Exempted {
			decision.Allow = false
			break
		}
	}
	return decision, nil
}

func (s *Service) CreateClusterSet(ctx context.Context, actor, orgID, name string, selector map[string]string) (*types.ClusterSet, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	cs := &types.ClusterSet{ID: "clusterset:" + newUUID(), OrgID: orgID, Name: name, LabelSelector: selector}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateClusterSet(ctx, tx, cs); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "cluster_set.created", ObjectType: "cluster_set", ObjectID: cs.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventClusterSetCreated, types.ClusterSetPayload{
			OrgID: orgID, ClusterSetID: cs.ID,
		})
	})
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func (s *Service) GetClusterSet(ctx context.Context, orgID, id string) (*types.ClusterSet, error) {
	cs, err := s.store.GetClusterSet(ctx, s.db.Pool, id)
	if err != nil {
		return nil, err
	}
	if cs.OrgID != orgID {
		return nil, ErrClusterSetNotFound
	}
	return cs, nil
}

func (s *Service) ListClusterSets(ctx context.Context, orgID string) ([]types.ClusterSet, error) {
	return s.store.ListClusterSets(ctx, s.db.Pool, orgID)
}

func (s *Service) DeleteClusterSet(ctx context.Context, actor, orgID, id string) error {
	if _, err := s.GetClusterSet(ctx, orgID, id); err != nil {
		return err
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.DeleteClusterSet(ctx, tx, id); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "cluster_set.deleted", ObjectType: "cluster_set", ObjectID: id,
		})
	})
}

func (s *Service) CreatePolicyPack(ctx context.Context, actor, orgID, name, engine, ociRef, version string, parameters, manifests json.RawMessage) (*types.PolicyPack, error) {
	if engine != types.PolicyPackEngineKyverno && engine != types.PolicyPackEngineCELVAP {
		return nil, fmt.Errorf("%w: engine must be kyverno|cel-vap", ErrInvalidInput)
	}
	if name == "" || version == "" {
		return nil, fmt.Errorf("%w: name and version are required", ErrInvalidInput)
	}
	var docs []json.RawMessage
	if err := json.Unmarshal(manifests, &docs); err != nil || len(docs) == 0 {
		return nil, fmt.Errorf("%w: manifests must be a non-empty JSON array", ErrInvalidInput)
	}
	if len(parameters) == 0 {
		parameters = json.RawMessage(`{}`)
	}
	p := &types.PolicyPack{
		ID: "policypack:" + newUUID(), OrgID: orgID, Name: name, Engine: engine,
		OCIRef: ociRef, Version: version, Parameters: parameters, Manifests: manifests,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreatePolicyPack(ctx, tx, p); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "policy_pack.created", ObjectType: "policy_pack", ObjectID: p.ID,
		})
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// GetPolicyPack returns one pack visible to the org (own or platform-global).
func (s *Service) GetPolicyPack(ctx context.Context, orgID, id string) (*types.PolicyPack, error) {
	p, err := s.store.GetPolicyPack(ctx, s.db.Pool, id)
	if err != nil {
		return nil, err
	}
	if p.OrgID != "" && p.OrgID != orgID {
		return nil, ErrPackNotFound
	}
	return p, nil
}

func (s *Service) ListPolicyPacks(ctx context.Context, orgID string) ([]types.PolicyPack, error) {
	return s.store.ListPolicyPacks(ctx, s.db.Pool, orgID)
}

func (s *Service) ListAssignments(ctx context.Context, orgID, packID string) ([]types.PolicyAssignment, error) {
	if _, err := s.GetPolicyPack(ctx, orgID, packID); err != nil {
		return nil, err
	}
	return s.store.ListAssignments(ctx, s.db.Pool, packID)
}

// Assign binds a pack to a ClusterSet / tenant / cluster, records audit +
// outbox (which drives the FGA tuple writer), then distributes the pack by
// enqueuing one ApplyBundle command per target cluster.
func (s *Service) Assign(ctx context.Context, actor, orgID, packID, targetType, targetID string) (*types.PolicyAssignment, error) {
	pack, err := s.GetPolicyPack(ctx, orgID, packID)
	if err != nil {
		return nil, err
	}
	clusters, err := s.targetClusters(ctx, orgID, targetType, targetID)
	if err != nil {
		return nil, err
	}
	a := &types.PolicyAssignment{
		ID: "policyassignment:" + newUUID(), PackID: packID, TargetType: targetType, TargetID: targetID,
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateAssignment(ctx, tx, a); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "policy_pack.assigned", ObjectType: "policy_pack", ObjectID: packID,
			Payload: json.RawMessage(fmt.Sprintf(`{"assignmentId":%q,"targetType":%q,"targetId":%q}`, a.ID, targetType, targetID)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventPolicyPackAssigned, types.PolicyPackAssignedPayload{
			OrgID: orgID, PackID: packID, AssignmentID: a.ID, TargetType: targetType, TargetID: targetID,
		})
	})
	if err != nil {
		return nil, err
	}
	if err := s.distribute(ctx, pack, clusters); err != nil {
		return nil, err
	}
	return a, nil
}

// Unassign removes one assignment. Reconciliation of already-applied pack
// manifests on target clusters is a Fleet Manager follow-up.
func (s *Service) Unassign(ctx context.Context, actor, orgID, packID, assignmentID string) error {
	if _, err := s.GetPolicyPack(ctx, orgID, packID); err != nil {
		return err
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.DeleteAssignment(ctx, tx, assignmentID); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "policy_pack.unassigned", ObjectType: "policy_pack", ObjectID: packID,
			Payload: json.RawMessage(fmt.Sprintf(`{"assignmentId":%q}`, assignmentID)),
		})
	})
}

// targetClusters validates the assignment target and resolves the member
// clusters to distribute to.
func (s *Service) targetClusters(ctx context.Context, orgID, targetType, targetID string) ([]types.Cluster, error) {
	switch targetType {
	case types.PolicyTargetClusterSet:
		cs, err := s.GetClusterSet(ctx, orgID, targetID)
		if err != nil {
			return nil, err
		}
		return s.ResolveClusters(ctx, orgID, cs.LabelSelector)
	case types.PolicyTargetTenant:
		if targetID != orgID {
			return nil, fmt.Errorf("%w: tenant target must be the caller's org", ErrInvalidInput)
		}
		return s.clusters.ListClusters(ctx, orgID)
	case types.PolicyTargetCluster:
		c, err := s.clusters.GetCluster(ctx, targetID)
		if err != nil {
			return nil, err
		}
		if c.OrgID != orgID {
			return nil, fmt.Errorf("%w: cluster does not belong to tenant", ErrInvalidInput)
		}
		return []types.Cluster{*c}, nil
	}
	return nil, fmt.Errorf("%w: targetType must be clusterset|tenant|cluster", ErrInvalidInput)
}

// distribute renders the pack bundle and enqueues one ApplyBundle command
// per target cluster (command ID is the idempotency key). The ApplyBundle
// proto's oneof source carries only OciRef or GitUrl — there is no inline
// manifests field — so an OCI-backed pack sets OciRef; a pack with inline
// manifests sends source unset with only the rendered-bundle checksum, and
// the documented gap is a follow-up: commit the rendered bundle to the
// tenant state repo and use the GitUrl source.
func (s *Service) distribute(ctx context.Context, pack *types.PolicyPack, clusters []types.Cluster) error {
	bundle, err := RenderPackBundle(pack)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bundle)
	checksum := hex.EncodeToString(sum[:])
	for _, c := range clusters {
		cmd := &agentv1.ApplyBundle{
			CommandId: "policypack:" + pack.ID,
			Checksum:  checksum,
		}
		if pack.OCIRef != "" {
			cmd.Source = &agentv1.ApplyBundle_OciRef{OciRef: pack.OCIRef}
		}
		any, err := anypb.New(cmd)
		if err != nil {
			return err
		}
		raw, err := protojson.Marshal(any)
		if err != nil {
			return err
		}
		if err := s.queue.Enqueue(ctx, &types.AgentCommand{
			ID:        "apply-bundle:policypack:" + pack.ID + ":" + c.ID,
			ClusterID: c.ID,
			Type:      agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_APPLY_BUNDLE),
			Payload:   raw,
		}); err != nil {
			return fmt.Errorf("policyservice: distribute to %s: %w", c.ID, err)
		}
	}
	return nil
}

// ResolveClusters returns the org's clusters whose labels contain every
// selector pair (subset match).
func (s *Service) ResolveClusters(ctx context.Context, orgID string, selector map[string]string) ([]types.Cluster, error) {
	all, err := s.clusters.ListClusters(ctx, orgID)
	if err != nil {
		return nil, err
	}
	var out []types.Cluster
	for _, c := range all {
		if matchesSelector(c.Labels, selector) {
			out = append(out, c)
		}
	}
	return out, nil
}

func matchesSelector(labels, selector map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// RequestExemption files a time-boxed waiver request for a policy (state
// pending; expiresAt must be future and ≤ 90 days out).
func (s *Service) RequestExemption(ctx context.Context, actor, orgID, policyID string, scope json.RawMessage, reason string, expiresAt time.Time) (*types.Exemption, error) {
	if _, err := s.GetPolicy(ctx, orgID, policyID); err != nil {
		return nil, err
	}
	if reason == "" {
		return nil, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	if err := validateExemptionExpiry(s.now(), expiresAt); err != nil {
		return nil, err
	}
	if len(scope) == 0 {
		scope = json.RawMessage(`{}`)
	}
	e := &types.Exemption{
		ID: "exemption:" + newUUID(), OrgID: orgID, PolicyID: policyID,
		Scope: scope, Reason: reason, State: types.ExemptionStatePending,
		ExpiresAt: expiresAt, CreatedBy: actor,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateExemption(ctx, tx, e); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "exemption.requested", ObjectType: "exemption", ObjectID: e.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventExemptionRequested, types.ExemptionPayload{
			OrgID: orgID, ExemptionID: e.ID, PolicyID: policyID, State: e.State,
		})
	})
	if err != nil {
		return nil, err
	}
	return e, nil
}

// DecideExemption approves or rejects a pending exemption.
func (s *Service) DecideExemption(ctx context.Context, actor, orgID, id string, approve bool) (*types.Exemption, error) {
	e, err := s.store.GetExemption(ctx, s.db.Pool, id)
	if err != nil {
		return nil, err
	}
	if e.OrgID != orgID {
		return nil, ErrExemptionNotFound
	}
	if e.State != types.ExemptionStatePending {
		return nil, ErrExemptionNotPending
	}
	state := types.ExemptionStateRejected
	action := "exemption.rejected"
	if approve {
		state = types.ExemptionStateApproved
		action = "exemption.approved"
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.SetExemptionState(ctx, tx, id, state, actor); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: action, ObjectType: "exemption", ObjectID: id,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventExemptionDecided, types.ExemptionPayload{
			OrgID: orgID, ExemptionID: id, PolicyID: e.PolicyID, State: state,
		})
	})
	if err != nil {
		return nil, err
	}
	e.State = state
	e.ApprovedBy = actor
	return e, nil
}

func (s *Service) ListExemptions(ctx context.Context, orgID string) ([]types.Exemption, error) {
	return s.store.ListExemptions(ctx, s.db.Pool, orgID)
}

func validateExemptionExpiry(now, expiresAt time.Time) error {
	if !expiresAt.After(now) {
		return fmt.Errorf("%w: expiresAt must be in the future", ErrInvalidInput)
	}
	if expiresAt.After(now.Add(MaxExemptionDuration)) {
		return fmt.Errorf("%w: expiresAt must be at most 90 days out", ErrInvalidInput)
	}
	return nil
}

func newUUID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}
