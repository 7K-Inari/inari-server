// Package platformresources implements the tenant platform resources module
// (plan §5.2, M7): control-plane-owned per-tenant platform objects (keycloak
// realm/client, dns-zone, tenant namespace). Provisioning writes desired
// state; the platform reconciler reports status back.
package platformresources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Service manages desired state and serves platform resource queries.
type Service struct {
	db    *db.DB
	store *Store
	audit *audit.Store
}

func NewService(d *db.DB, store *Store, auditStore *audit.Store) *Service {
	return &Service{db: d, store: store, audit: auditStore}
}

// List returns all platform resources for an org.
func (s *Service) List(ctx context.Context, orgID string) ([]types.PlatformResource, error) {
	return s.store.List(ctx, s.db.Pool, orgID)
}

// Get returns one resource; a mismatched org is reported as not found (no
// cross-tenant existence leak).
func (s *Service) Get(ctx context.Context, orgID, id string) (*types.PlatformResource, error) {
	r, err := s.store.Get(ctx, s.db.Pool, id)
	if err != nil {
		return nil, err
	}
	if r.OrgID != orgID {
		return nil, ErrResourceNotFound
	}
	return r, nil
}

// EnsureDesired idempotently upserts the desired state for (org, kind, name).
// Audit + outbox events are emitted only when the row is new or the desired
// state changed, so repeat calls are side-effect free.
func (s *Service) EnsureDesired(ctx context.Context, orgID string, kind types.PlatformResourceKind, name string, desired json.RawMessage) (*types.PlatformResource, error) {
	if !kind.Valid() {
		return nil, fmt.Errorf("platformresources: invalid kind %q", kind)
	}
	if orgID == "" || name == "" {
		return nil, fmt.Errorf("platformresources: orgID and name must not be empty")
	}
	if len(desired) == 0 {
		desired = json.RawMessage(`{}`)
	}
	var out *types.PlatformResource
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		r, changed, err := s.store.UpsertDesired(ctx, tx, &types.PlatformResource{
			ID: uuid.NewString(), OrgID: orgID, Kind: kind, Name: name, Desired: desired,
		})
		if err != nil {
			return err
		}
		out = r
		if !changed {
			return nil
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: "system", Action: "platform_resource.ensure_desired",
			ObjectType: "platform_resource", ObjectID: r.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventPlatformResourceStatus, types.PlatformResourcePayload{
			OrgID: orgID, ResourceID: r.ID, Kind: r.Kind, Name: r.Name, Status: r.Status,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("platformresources: ensure desired: %w", err)
	}
	return out, nil
}

// ApplyStatus records a reconciler status report for one resource. Stub for
// now: the status sink wiring is a separate task.
func (s *Service) ApplyStatus(ctx context.Context, id string, status types.PlatformResourceStatus, detail string) (*types.PlatformResource, error) {
	if !status.Valid() {
		return nil, fmt.Errorf("platformresources: invalid status %q", status)
	}
	var out *types.PlatformResource
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		r, err := s.store.ApplyStatus(ctx, tx, id, status, detail)
		if err != nil {
			return err
		}
		out = r
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: r.OrgID, Actor: "reconciler", Action: "platform_resource.status",
			ObjectType: "platform_resource", ObjectID: r.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, r.OrgID, types.EventPlatformResourceStatus, types.PlatformResourcePayload{
			OrgID: r.OrgID, ResourceID: r.ID, Kind: r.Kind, Name: r.Name, Status: r.Status,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("platformresources: apply status: %w", err)
	}
	return out, nil
}
