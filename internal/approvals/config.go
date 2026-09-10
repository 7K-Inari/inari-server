// Per-org approval policy config (Settings design §2): a JSONB blob per
// org, merged over built-in defaults at read time. Consumed by the
// approvals lifecycle as an override layer — evaluation wiring is a
// follow-up pending the policy-service contract (M3).
package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrInvalidConfig is returned when a config fails validation.
var ErrInvalidConfig = errors.New("approvals: invalid config")

// DefaultConfig is the effective config for orgs without a stored row.
func DefaultConfig() types.ApprovalConfig {
	return types.ApprovalConfig{
		DefaultPolicy: types.ApprovalPolicyAuto,
		ApprovalTTL:   DefaultTTL.String(),
	}
}

func validateConfig(c *types.ApprovalConfig) error {
	if !c.DefaultPolicy.Valid() {
		return fmt.Errorf("%w: unknown default policy %q", ErrInvalidConfig, c.DefaultPolicy)
	}
	ttl, err := c.TTLDuration()
	if err != nil {
		return fmt.Errorf("%w: malformed approval_ttl %q", ErrInvalidConfig, c.ApprovalTTL)
	}
	if ttl <= 0 {
		return fmt.Errorf("%w: approval_ttl must be positive", ErrInvalidConfig)
	}
	for _, th := range c.Thresholds {
		if th.Kind == "" {
			return fmt.Errorf("%w: threshold kind required", ErrInvalidConfig)
		}
		if th.Gt < 0 {
			return fmt.Errorf("%w: threshold gt must be >= 0", ErrInvalidConfig)
		}
		if !th.Policy.Valid() {
			return fmt.Errorf("%w: threshold unknown policy %q", ErrInvalidConfig, th.Policy)
		}
	}
	for _, g := range c.ApproverGroups {
		if g.Name == "" {
			return fmt.Errorf("%w: approver group name required", ErrInvalidConfig)
		}
		if len(g.Subjects) == 0 {
			return fmt.Errorf("%w: approver group %q needs subjects", ErrInvalidConfig, g.Name)
		}
	}
	for _, r := range c.AutoApprove {
		if r.Kind == "" {
			return fmt.Errorf("%w: auto-approve rule kind required", ErrInvalidConfig)
		}
		if len(r.ItemIDs) == 0 {
			return fmt.Errorf("%w: auto-approve rule needs item ids", ErrInvalidConfig)
		}
	}
	return nil
}

// getConfig loads the stored config row; found=false when none exists.
func (s *Store) getConfig(ctx context.Context, q db.Querier, orgID string) (*types.ApprovalConfigRecord, bool, error) {
	const sql = `SELECT config, updated_at FROM approval_config WHERE org_id = $1`
	var raw []byte
	rec := &types.ApprovalConfigRecord{OrgID: orgID}
	err := q.QueryRow(ctx, sql, orgID).Scan(&raw, &rec.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := json.Unmarshal(raw, &rec.Config); err != nil {
		return nil, false, fmt.Errorf("approvals: decode config for %s: %w", orgID, err)
	}
	return rec, true, nil
}

func (s *Store) upsertConfig(ctx context.Context, q db.Querier, orgID string, cfg *types.ApprovalConfig) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	const sql = `INSERT INTO approval_config (org_id, config) VALUES ($1, $2)
	             ON CONFLICT (org_id) DO UPDATE SET config = EXCLUDED.config, updated_at = now()`
	_, err = q.Exec(ctx, sql, orgID, raw)
	return err
}

// GetConfig returns the effective config for an org — the stored row, or
// defaults when none exists.
func (s *Service) GetConfig(ctx context.Context, orgID string) (*types.ApprovalConfigRecord, error) {
	rec, found, err := s.store.getConfig(ctx, s.db.Pool, orgID)
	if err != nil {
		return nil, err
	}
	if !found {
		return &types.ApprovalConfigRecord{OrgID: orgID, Config: DefaultConfig()}, nil
	}
	return rec, nil
}

// UpdateConfig validates and replaces the org's config, recording an audit
// event with the before/after effective configs plus an outbox row.
func (s *Service) UpdateConfig(ctx context.Context, actor, orgID string, cfg types.ApprovalConfig) (*types.ApprovalConfigRecord, error) {
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	var rec *types.ApprovalConfigRecord
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		before, found, err := s.store.getConfig(ctx, tx, orgID)
		if err != nil {
			return err
		}
		beforeCfg := DefaultConfig()
		if found {
			beforeCfg = before.Config
		}
		if err := s.store.upsertConfig(ctx, tx, orgID, &cfg); err != nil {
			return err
		}
		payload, err := json.Marshal(types.ApprovalConfigPayload{
			OrgID: orgID, Before: &beforeCfg, After: &cfg,
		})
		if err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: types.EventApprovalConfigUpdated,
			ObjectType: "approval_config", ObjectID: orgID,
			Payload: payload,
		}); err != nil {
			return err
		}
		if err := audit.AppendOutbox(ctx, tx, orgID, types.EventApprovalConfigUpdated, types.ApprovalConfigPayload{
			OrgID: orgID, Before: &beforeCfg, After: &cfg,
		}); err != nil {
			return err
		}
		stored, _, err := s.store.getConfig(ctx, tx, orgID)
		if err != nil {
			return err
		}
		rec = stored
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rec, nil
}
