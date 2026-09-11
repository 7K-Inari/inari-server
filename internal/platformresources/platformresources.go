// Package platformresources implements the tenant platform resources module
// (plan §5.2, M7): control-plane-owned per-tenant platform objects (keycloak
// realm/client, dns-zone, tenant namespace). Provisioning writes desired
// state; the platform reconciler reports status back.
package platformresources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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

// platformKindSuffix marks agent-reported CRDs owned by the platform
// reconciler (ResourceRef.kind = "<Kind>.platform.inari.io").
const platformKindSuffix = ".platform.inari.io"

// StatusUpdate is the internal form of an agent status-update event for one
// platform CRD (mirrors the inventory seam's shape).
type StatusUpdate struct {
	Resource   types.ResourceRef
	Health     string
	Message    string
	ObservedAt time.Time
}

// IsPlatformKind reports whether an agent resource kind belongs to the
// platform CRD group (routing predicate for the status sink).
func IsPlatformKind(kind string) bool {
	return strings.HasSuffix(kind, platformKindSuffix) && len(kind) > len(platformKindSuffix)
}

// KindForCRD maps an agent CRD kind to the platform resource kind recorded
// at EnsureDesired time. DNSZone and DNSRecord both report against the
// dns-zone row (records live under their zone's name).
func KindForCRD(crd string) (types.PlatformResourceKind, bool) {
	if !IsPlatformKind(crd) {
		return "", false
	}
	switch strings.TrimSuffix(crd, platformKindSuffix) {
	case "KeycloakRealm":
		return types.PlatformKindKeycloakRealm, true
	case "KeycloakClient":
		return types.PlatformKindKeycloakClient, true
	case "DNSZone", "DNSRecord":
		return types.PlatformKindDNSZone, true
	case "TenantNamespace":
		return types.PlatformKindTenantNamespace, true
	}
	return "", false
}

// deriveStatus maps agent health to the platform resource status.
func deriveStatus(health string) types.PlatformResourceStatus {
	switch health {
	case "healthy":
		return types.PlatformStatusReady
	case "degraded":
		return types.PlatformStatusFailed
	default: // progressing, unknown
		return types.PlatformStatusReconciling
	}
}

// ApplyStatus folds one agent status-update into the matching platform
// resource row (matched on kind+name; CR names embed the tenant slug and are
// recorded at EnsureDesired time). Unknown or unmatched updates are ignored
// without error, mirroring inventory's drop-and-log contract.
func (s *Service) ApplyStatus(ctx context.Context, clusterID string, upd StatusUpdate) (bool, error) {
	kind, ok := KindForCRD(upd.Resource.Kind)
	if !ok {
		return false, nil
	}
	status := deriveStatus(upd.Health)
	var matched bool
	var r *types.PlatformResource
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		var err error
		var observedAt *time.Time
		if !upd.ObservedAt.IsZero() {
			observedAt = &upd.ObservedAt
		}
		r, matched, err = s.store.ApplyStatus(ctx, tx, kind, upd.Resource.Name, status, upd.Message, observedAt)
		if err != nil || !matched {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: r.OrgID, Actor: "agent:" + clusterID, Action: "platform-resource.status",
			ObjectType: "platform_resource", ObjectID: r.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, r.OrgID, types.EventPlatformResourceStatus, types.PlatformResourcePayload{
			OrgID: r.OrgID, ResourceID: r.ID, Kind: r.Kind, Name: r.Name, Status: r.Status,
		})
	})
	if err != nil {
		return false, fmt.Errorf("platformresources: apply status: %w", err)
	}
	return matched, nil
}
