package featureflags

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/cache"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/metrics"
	"github.com/7K-Inari/inari-server/internal/types"
)

// GenerationKey is the shared invalidation counter for the flag read cache
// (same generation-bump pattern as authz pepGenerationKey): every flag write
// bumps it, so stale entries from earlier generations are never read again.
const GenerationKey = "inari:flags:gen"

// EventFeatureFlagsUpdated is the outbox event appended on every flag
// write/delete (audit trail + future relay consumers).
const EventFeatureFlagsUpdated = "featureflags.updated"

// Validation errors returned by Set/Clear.
var (
	ErrUnknownFlag = errors.New("featureflags: unknown flag key")
	ErrBadScope    = errors.New("featureflags: scope not allowed for this flag")
)

// UpdatedPayload is the outbox payload for EventFeatureFlagsUpdated.
type UpdatedPayload struct {
	FlagKey   string `json:"flagKey"`
	Scope     string `json:"scope"`
	ScopeKey  string `json:"scopeKey,omitempty"`
	Value     *bool  `json:"value"` // nil = cleared (reverted)
	UpdatedBy string `json:"updatedBy"`
}

// Service writes flag values with audit + outbox in one TX and bumps the
// read-cache generation after commit (InvalidatingStore precedent).
type Service struct {
	db      *db.DB
	store   *Store
	audit   *audit.Store
	cache   cache.Cache
	backend string
}

// NewService builds the flag write path. cache may be nil (bump skipped —
// callers then rely on TTL for cross-replica propagation).
func NewService(d *db.DB, store *Store, auditStore *audit.Store, c cache.Cache, backend string) *Service {
	return &Service{db: d, store: store, audit: auditStore, cache: c, backend: backend}
}

// Set writes value for (key, scope, scopeKey). orgID scopes the audit +
// outbox rows ("" for platform-scope writes).
func (s *Service) Set(ctx context.Context, actor, orgID, key string, scope Scope, scopeKey string, value bool) error {
	if _, err := validate(key, scope); err != nil {
		return err
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.Upsert(ctx, tx, Row{FlagKey: key, Scope: scope, ScopeKey: scopeKey, Value: value, UpdatedBy: actor}); err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]any{"flagKey": key, "scope": string(scope), "scopeKey": scopeKey, "value": value})
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "featureflags.set",
			ObjectType: "feature_flag", ObjectID: key + "/" + string(scope) + "/" + scopeKey,
			Payload: payload,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, EventFeatureFlagsUpdated, UpdatedPayload{
			FlagKey: key, Scope: string(scope), ScopeKey: scopeKey, Value: &value, UpdatedBy: actor,
		})
	})
	if err != nil {
		return fmt.Errorf("featureflags: set: %w", err)
	}
	s.bump(ctx)
	return nil
}

// Clear removes the row for (key, scope, scopeKey), reverting to the wider
// scope or the built-in default.
func (s *Service) Clear(ctx context.Context, actor, orgID, key string, scope Scope, scopeKey string) error {
	if _, err := validate(key, scope); err != nil {
		return err
	}
	var deleted bool
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		var err error
		deleted, err = s.store.Delete(ctx, tx, key, scope, scopeKey)
		if err != nil {
			return err
		}
		if !deleted {
			return nil
		}
		payload, _ := json.Marshal(map[string]any{"flagKey": key, "scope": string(scope), "scopeKey": scopeKey, "value": nil})
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "featureflags.cleared",
			ObjectType: "feature_flag", ObjectID: key + "/" + string(scope) + "/" + scopeKey,
			Payload: payload,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, EventFeatureFlagsUpdated, UpdatedPayload{
			FlagKey: key, Scope: string(scope), ScopeKey: scopeKey, Value: nil, UpdatedBy: actor,
		})
	})
	if err != nil {
		return fmt.Errorf("featureflags: clear: %w", err)
	}
	if deleted {
		s.bump(ctx)
	}
	return nil
}

// List returns every persisted row for a flag key.
func (s *Service) List(ctx context.Context, key string) ([]Row, error) {
	return s.store.List(ctx, s.db.Pool, key)
}

// Get returns the row for one exact (key, scope, scopeKey), nil when absent.
func (s *Service) Get(ctx context.Context, key string, scope Scope, scopeKey string) (*Row, error) {
	return s.store.Get(ctx, s.db.Pool, key, scope, scopeKey)
}

// bump invalidates all cached flag reads; fail-open (TTL bounds staleness).
func (s *Service) bump(ctx context.Context) {
	if s.cache == nil {
		return
	}
	if _, err := s.cache.Increment(ctx, GenerationKey); err != nil {
		metrics.RecordCacheOp(ctx, metrics.CacheFlags, s.backend, metrics.OpIncrement, metrics.ResultError)
		slog.Warn("featureflags: cache invalidation failed (fail-open; TTL bounds staleness)", "error", err)
		return
	}
	metrics.RecordInvalidation(ctx, metrics.CacheFlags)
}

func validate(key string, scope Scope) (Definition, error) {
	def, ok := Lookup(key)
	if !ok {
		return Definition{}, ErrUnknownFlag
	}
	if !def.AllowsScope(scope) {
		return Definition{}, ErrBadScope
	}
	return def, nil
}
