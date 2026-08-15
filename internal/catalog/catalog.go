package catalog

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// CapabilityLister reads live discovered capabilities (capabilities.Store).
type CapabilityLister interface {
	List(ctx context.Context, q db.Querier, clusterID string) ([]types.Capability, error)
}

// Service is the Catalog Service facade (plan §5.5).
type Service struct {
	db     *db.DB
	store  *Store
	caps   CapabilityLister
	audit  *audit.Store
	puller OCIPuller // nil when sync is not configured
}

func NewService(d *db.DB, store *Store, caps CapabilityLister, auditStore *audit.Store, puller OCIPuller) *Service {
	return &Service{db: d, store: store, caps: caps, audit: auditStore, puller: puller}
}

// ItemView is a catalog item plus its versions for list responses.
type ItemView struct {
	types.CatalogItem
	Versions []types.CatalogItemVersion `json:"versions,omitempty"`
	// PinnedVersion is the tenant's pin, when set.
	PinnedVersion string `json:"pinnedVersion,omitempty"`
}

// UpsertItem creates or updates an item + one version with audit + outbox.
func (s *Service) UpsertItem(ctx context.Context, item *types.CatalogItem, version *types.CatalogItemVersion) error {
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpsertItem(ctx, tx, item); err != nil {
			return err
		}
		if version != nil {
			if err := s.store.UpsertVersion(ctx, tx, version); err != nil {
				return err
			}
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: "platform", Actor: "system:catalog-sync", Action: "catalog.item_upserted",
			ObjectType: "catalog_item", ObjectID: item.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, "platform", types.EventCatalogItemUpserted, types.CatalogItemPayload{
			ItemID: item.ID, Source: string(item.Source),
		})
	})
	if err != nil {
		return fmt.Errorf("catalog: upsert item %s: %w", item.ID, err)
	}
	return nil
}

// ListVisible returns the items visible to a tenant, optionally intersected
// with a cluster's discovered capabilities ("what can I run here?", §8/G9).
func (s *Service) ListVisible(ctx context.Context, orgID, clusterID string) ([]ItemView, error) {
	items, err := s.store.ListItems(ctx, s.db.Pool)
	if err != nil {
		return nil, err
	}
	visMap, err := s.store.VisibilityMap(ctx, s.db.Pool)
	if err != nil {
		return nil, err
	}
	var out []ItemView
	visible := make([]types.CatalogItem, 0, len(items))
	for _, it := range items {
		if visibleTo(visMap[it.ID], orgID, clusterID) {
			visible = append(visible, it)
		}
	}
	ids := make([]string, 0, len(visible))
	for _, it := range visible {
		ids = append(ids, it.ID)
	}
	versionsByItem, err := s.store.ListVersionsForItems(ctx, s.db.Pool, ids)
	if err != nil {
		return nil, err
	}
	pins, err := s.store.PinsForOrg(ctx, s.db.Pool, orgID)
	if err != nil {
		return nil, err
	}
	for _, it := range visible {
		out = append(out, ItemView{CatalogItem: it, Versions: versionsByItem[it.ID], PinnedVersion: pins[it.ID]})
	}
	if clusterID != "" && s.caps != nil {
		caps, err := s.caps.List(ctx, s.db.Pool, clusterID)
		if err != nil {
			return nil, err
		}
		for _, it := range projectDiscovered(clusterID, caps) {
			out = append(out, ItemView{CatalogItem: it})
		}
	}
	return out, nil
}

// GetItem returns one item with its versions, enforcing visibility.
func (s *Service) GetItem(ctx context.Context, orgID, clusterID, itemID string) (*ItemView, error) {
	it, err := s.store.GetItem(ctx, s.db.Pool, itemID)
	if err != nil {
		return nil, err
	}
	visMap, err := s.store.VisibilityMap(ctx, s.db.Pool)
	if err != nil {
		return nil, err
	}
	if !visibleTo(visMap[it.ID], orgID, clusterID) {
		return nil, ErrItemNotFound
	}
	versions, err := s.store.ListVersions(ctx, s.db.Pool, it.ID)
	if err != nil {
		return nil, err
	}
	pin, err := s.store.GetPin(ctx, s.db.Pool, orgID, it.ID)
	if err != nil {
		return nil, err
	}
	return &ItemView{CatalogItem: *it, Versions: versions, PinnedVersion: pin}, nil
}

// GetItemByID returns an item without visibility checks (approvals seam).
func (s *Service) GetItemByID(ctx context.Context, itemID string) (*types.CatalogItem, error) {
	return s.store.GetItem(ctx, s.db.Pool, itemID)
}

// EnsureVisible enforces per-tenant/cluster visibility policies for flows
// that load items by ID directly (orchestrator deploy). Hidden items read
// as not-found.
func (s *Service) EnsureVisible(ctx context.Context, orgID, clusterID, itemID string) error {
	if _, err := s.store.GetItem(ctx, s.db.Pool, itemID); err != nil {
		return err
	}
	visMap, err := s.store.VisibilityMap(ctx, s.db.Pool)
	if err != nil {
		return err
	}
	if !visibleTo(visMap[itemID], orgID, clusterID) {
		return ErrItemNotFound
	}
	return nil
}

// EffectiveVersion resolves the version a tenant deploys: pin wins,
// otherwise the latest in the channel (default "stable").
func (s *Service) EffectiveVersion(ctx context.Context, orgID, itemID, channel string) (string, error) {
	pin, err := s.store.GetPin(ctx, s.db.Pool, orgID, itemID)
	if err != nil {
		return "", err
	}
	if pin != "" {
		return pin, nil
	}
	versions, err := s.store.ListVersions(ctx, s.db.Pool, itemID)
	if err != nil {
		return "", err
	}
	latest := latestInChannel(versions, channel)
	if latest == "" {
		return "", fmt.Errorf("catalog: no version of %s in channel %q", itemID, channel)
	}
	return latest, nil
}

// LatestVersion returns the newest version in a channel ("" = stable),
// ignoring pins — used for "new version available" badges.
func (s *Service) LatestVersion(ctx context.Context, itemID, channel string) (string, error) {
	versions, err := s.store.ListVersions(ctx, s.db.Pool, itemID)
	if err != nil {
		return "", err
	}
	if channel == "" {
		channel = "stable"
	}
	return latestInChannel(versions, channel), nil
}

// LatestVersions returns item_id → newest stable version for many items in
// one query (inventory badge fan-out).
func (s *Service) LatestVersions(ctx context.Context, itemIDs []string) (map[string]string, error) {
	byItem, err := s.store.ListVersionsForItems(ctx, s.db.Pool, itemIDs)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for id, versions := range byItem {
		if latest := latestInChannel(versions, "stable"); latest != "" {
			out[id] = latest
		}
	}
	return out, nil
}

// GetVersion returns one version row.
func (s *Service) GetVersion(ctx context.Context, itemID, version string) (*types.CatalogItemVersion, error) {
	versions, err := s.store.ListVersions(ctx, s.db.Pool, itemID)
	if err != nil {
		return nil, err
	}
	for i := range versions {
		if versions[i].Version == version {
			return &versions[i], nil
		}
	}
	return nil, ErrVersionNotFound
}

// SetPin pins a tenant to a version. The version must exist.
func (s *Service) SetPin(ctx context.Context, actor, orgID, itemID, version string) error {
	if _, err := s.GetVersion(ctx, itemID, version); err != nil {
		return err
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.SetPin(ctx, tx, &types.VersionPin{OrgID: orgID, ItemID: itemID, Version: version}); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "catalog.pin_set",
			ObjectType: "catalog_item", ObjectID: itemID,
			Payload: json.RawMessage(fmt.Sprintf(`{"version":%q}`, version)),
		})
	})
	return err
}

func (s *Service) DeletePin(ctx context.Context, actor, orgID, itemID string) error {
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.DeletePin(ctx, tx, orgID, itemID); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "catalog.pin_removed",
			ObjectType: "catalog_item", ObjectID: itemID,
		})
	})
}

// SetVisibility replaces visibility rules for an item.
func (s *Service) SetVisibility(ctx context.Context, actor string, rules []types.VisibilityRule) error {
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.SetVisibility(ctx, tx, rules); err != nil {
			return err
		}
		for _, r := range rules {
			if err := s.audit.Record(ctx, tx, &types.AuditEvent{
				OrgID: "platform", Actor: actor, Action: "catalog.visibility_set",
				ObjectType: "catalog_item", ObjectID: r.ItemID,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// PlatformApps is the M2 stub list of platform-cluster apps (plan §5.5
// source 3). It is seeded at startup via SeedPlatformApps.
var PlatformApps = []types.CatalogItem{
	{ID: "platform:keycloak", Source: types.CatalogSourcePlatform, Name: "keycloak", DisplayName: "Keycloak", Description: "Identity and access management"},
	{ID: "platform:cert-manager", Source: types.CatalogSourcePlatform, Name: "cert-manager", DisplayName: "cert-manager", Description: "X.509 certificate management"},
	{ID: "platform:external-secrets", Source: types.CatalogSourcePlatform, Name: "external-secrets", DisplayName: "External Secrets Operator", Description: "Synchronize secrets from external backends"},
	{ID: "platform:argocd", Source: types.CatalogSourcePlatform, Name: "argocd", DisplayName: "ArgoCD", Description: "GitOps continuous delivery"},
}

// SeedPlatformApps upserts the stub platform app catalog items idempotently.
func (s *Service) SeedPlatformApps(ctx context.Context) error {
	for i := range PlatformApps {
		if err := s.UpsertItem(ctx, &PlatformApps[i], nil); err != nil {
			return err
		}
	}
	return nil
}
