package resourcetargets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// AuthzSync converges current DB target/grant state into OpenFGA. Event
// payloads identify the target; stale event snapshots never overwrite newer DB state.
type AuthzSync struct {
	db    *db.DB
	store *Store
	fga   authz.Store
}

func NewAuthzSync(d *db.DB, store *Store, fga authz.Store) *AuthzSync {
	return &AuthzSync{db: d, store: store, fga: fga}
}

func (s *AuthzSync) EventTypes() []string {
	return []string{types.EventResourceTargetCreated, types.EventResourceTargetUpdated,
		types.EventResourceTargetDeleted, types.EventResourceTargetGrantChanged}
}

func (s *AuthzSync) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	var payload types.ResourceTargetPayload
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		return err
	}
	if payload.OrgID == "" || payload.TargetID == "" {
		return fmt.Errorf("resourcetargets: authz event missing org or target")
	}
	return s.SyncTarget(ctx, payload.OrgID, payload.TargetID)
}

func grantObjectRelation(action Action) (string, error) {
	switch action {
	case ActionView:
		return authz.RelationViewGrant, nil
	case ActionUse:
		return authz.RelationUseGrant, nil
	case ActionProvision:
		return authz.RelationProvisionGrant, nil
	default:
		return "", fmt.Errorf("resourcetargets: invalid grant relation %q", action)
	}
}

func authzTupleKey(tuple authz.Tuple) string {
	return tuple.User + "|" + tuple.Relation + "|" + tuple.Object
}

func (s *AuthzSync) SyncTarget(ctx context.Context, orgID, targetID string) error {
	desired := map[string]authz.Tuple{}
	_, err := s.store.Get(ctx, s.db.Pool, orgID, targetID)
	if err == nil {
		object := authz.ResourceTargetObject(targetID)
		parent := authz.Tuple{User: authz.OrgObject(orgID), Relation: authz.RelationParent, Object: object}
		desired[authzTupleKey(parent)] = parent
		grants, err := s.store.ListGrants(ctx, s.db.Pool, orgID, targetID)
		if err != nil {
			return err
		}
		for _, grant := range grants {
			relation, err := grantObjectRelation(grant.Relation)
			if err != nil {
				return err
			}
			tuple := authz.Tuple{User: authz.TeamMemberUserset(grant.TeamID), Relation: relation, Object: object}
			desired[authzTupleKey(tuple)] = tuple
		}
	} else if !errors.Is(err, ErrTargetNotFound) {
		return err
	}

	object := authz.ResourceTargetObject(targetID)
	existing := map[string]authz.Tuple{}
	for _, relation := range []string{authz.RelationParent, authz.RelationViewGrant, authz.RelationUseGrant, authz.RelationProvisionGrant} {
		tuples, err := s.fga.ReadTuples(ctx, object, relation)
		if err != nil {
			return err
		}
		for _, tuple := range tuples {
			existing[authzTupleKey(tuple)] = tuple
		}
	}
	var remove, add []authz.Tuple
	for key, tuple := range existing {
		if _, ok := desired[key]; !ok {
			remove = append(remove, tuple)
		}
	}
	for key, tuple := range desired {
		if _, ok := existing[key]; !ok {
			add = append(add, tuple)
		}
	}
	if len(remove) > 0 {
		if err := s.fga.DeleteTuples(ctx, remove); err != nil {
			return err
		}
	}
	if len(add) > 0 {
		if err := s.fga.WriteTuples(ctx, add); err != nil {
			return err
		}
	}
	return nil
}

func (s *AuthzSync) SyncAll(ctx context.Context) error {
	targets, err := s.store.ListAll(ctx, s.db.Pool)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if err := s.SyncTarget(ctx, target.OrgID, target.ID); err != nil {
			return fmt.Errorf("resourcetargets: sync %s: %w", target.ID, err)
		}
	}
	return nil
}

func (s *AuthzSync) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.SyncAll(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("resource target authz convergence failed", "error", err)
			}
		}
	}
}
