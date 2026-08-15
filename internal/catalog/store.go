package catalog

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrItemNotFound is returned when a catalog item does not exist.
var ErrItemNotFound = errors.New("catalog: item not found")

// ErrVersionNotFound is returned when a catalog item version does not exist.
var ErrVersionNotFound = errors.New("catalog: version not found")

// Store is the PostgreSQL projection of curated/platform catalog items,
// versions, visibility rules, and tenant pins.
type Store struct{}

func NewStore() *Store { return &Store{} }

func (s *Store) UpsertItem(ctx context.Context, q db.Querier, it *types.CatalogItem) error {
	var ref any
	if it.CapabilityRef != nil {
		raw, err := json.Marshal(it.CapabilityRef)
		if err != nil {
			return err
		}
		ref = raw
	}
	policy := it.ApprovalPolicy
	if policy == "" {
		policy = types.ApprovalPolicyAuto
	}
	const sql = `INSERT INTO catalog_items (id, source, name, display_name, description, capability_ref, oci_ref, approval_policy)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	             ON CONFLICT (id) DO UPDATE SET
	               source = EXCLUDED.source,
	               name = EXCLUDED.name,
	               display_name = EXCLUDED.display_name,
	               description = EXCLUDED.description,
	               capability_ref = EXCLUDED.capability_ref,
	               oci_ref = EXCLUDED.oci_ref`
	_, err := q.Exec(ctx, sql, it.ID, it.Source, it.Name, it.DisplayName, it.Description, ref, it.OCIRef, policy)
	return err
}

func (s *Store) UpsertVersion(ctx context.Context, q db.Querier, v *types.CatalogItemVersion) error {
	channel := v.Channel
	if channel == "" {
		channel = "stable"
	}
	const sql = `INSERT INTO catalog_item_versions (item_id, version, channel, schema, ui_hints, payload)
	             VALUES ($1,$2,$3,$4,$5,$6)
	             ON CONFLICT (item_id, version) DO UPDATE SET
	               channel = EXCLUDED.channel,
	               schema = EXCLUDED.schema,
	               ui_hints = EXCLUDED.ui_hints,
	               payload = EXCLUDED.payload`
	_, err := q.Exec(ctx, sql, v.ItemID, v.Version, channel, nullJSON(v.Schema), nullJSON(v.UIHints), nullJSON(v.Payload))
	return err
}

func scanItem(row pgx.Row) (*types.CatalogItem, error) {
	var it types.CatalogItem
	var ref json.RawMessage
	err := row.Scan(&it.ID, &it.Source, &it.Name, &it.DisplayName, &it.Description,
		&ref, &it.OCIRef, &it.ApprovalPolicy, &it.CreatedAt)
	if err != nil {
		return nil, err
	}
	if len(ref) > 0 {
		var cr types.CapabilityRef
		if err := json.Unmarshal(ref, &cr); err == nil {
			it.CapabilityRef = &cr
		}
	}
	return &it, nil
}

const itemCols = `id, source, name, display_name, description, capability_ref, oci_ref, approval_policy, created_at`

func (s *Store) GetItem(ctx context.Context, q db.Querier, itemID string) (*types.CatalogItem, error) {
	it, err := scanItem(q.QueryRow(ctx, `SELECT `+itemCols+` FROM catalog_items WHERE id = $1`, itemID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrItemNotFound
	}
	return it, err
}

func (s *Store) ListItems(ctx context.Context, q db.Querier) ([]types.CatalogItem, error) {
	rows, err := q.Query(ctx, `SELECT `+itemCols+` FROM catalog_items ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.CatalogItem
	for rows.Next() {
		it, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *it)
	}
	return out, rows.Err()
}

func (s *Store) ListVersions(ctx context.Context, q db.Querier, itemID string) ([]types.CatalogItemVersion, error) {
	const sql = `SELECT item_id, version, channel, schema, ui_hints, payload
	             FROM catalog_item_versions WHERE item_id = $1 ORDER BY version`
	rows, err := q.Query(ctx, sql, itemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.CatalogItemVersion
	for rows.Next() {
		var v types.CatalogItemVersion
		if err := rows.Scan(&v.ItemID, &v.Version, &v.Channel, &v.Schema, &v.UIHints, &v.Payload); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ListVersionsForItems returns versions grouped by item ID in one query.
func (s *Store) ListVersionsForItems(ctx context.Context, q db.Querier, itemIDs []string) (map[string][]types.CatalogItemVersion, error) {
	const sql = `SELECT item_id, version, channel, schema, ui_hints, payload
	             FROM catalog_item_versions WHERE item_id = ANY($1) ORDER BY version`
	rows, err := q.Query(ctx, sql, itemIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]types.CatalogItemVersion{}
	for rows.Next() {
		var v types.CatalogItemVersion
		if err := rows.Scan(&v.ItemID, &v.Version, &v.Channel, &v.Schema, &v.UIHints, &v.Payload); err != nil {
			return nil, err
		}
		out[v.ItemID] = append(out[v.ItemID], v)
	}
	return out, rows.Err()
}

// PinsForOrg returns item_id → pinned version for a tenant in one query.
func (s *Store) PinsForOrg(ctx context.Context, q db.Querier, orgID string) (map[string]string, error) {
	rows, err := q.Query(ctx, `SELECT item_id, version FROM catalog_pins WHERE org_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, v string
		if err := rows.Scan(&id, &v); err != nil {
			return nil, err
		}
		out[id] = v
	}
	return out, rows.Err()
}

// SetVisibility replaces all visibility rules for the affected items.
func (s *Store) SetVisibility(ctx context.Context, q db.Querier, rules []types.VisibilityRule) error {
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.ItemID] {
			continue
		}
		seen[r.ItemID] = true
		if _, err := q.Exec(ctx, `DELETE FROM catalog_visibility WHERE item_id = $1`, r.ItemID); err != nil {
			return err
		}
	}
	for _, r := range rules {
		cluster := r.ClusterID
		if cluster == "" {
			cluster = "*"
		}
		const sql = `INSERT INTO catalog_visibility (item_id, org_id, cluster_id) VALUES ($1,$2,$3)
		             ON CONFLICT (item_id, org_id, cluster_id) DO NOTHING`
		if _, err := q.Exec(ctx, sql, r.ItemID, r.OrgID, cluster); err != nil {
			return err
		}
	}
	return nil
}

// VisibilityMap returns item_id → rules for all items.
func (s *Store) VisibilityMap(ctx context.Context, q db.Querier) (map[string][]types.VisibilityRule, error) {
	rows, err := q.Query(ctx, `SELECT item_id, org_id, cluster_id FROM catalog_visibility`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]types.VisibilityRule{}
	for rows.Next() {
		var r types.VisibilityRule
		if err := rows.Scan(&r.ItemID, &r.OrgID, &r.ClusterID); err != nil {
			return nil, err
		}
		out[r.ItemID] = append(out[r.ItemID], r)
	}
	return out, rows.Err()
}

func (s *Store) SetPin(ctx context.Context, q db.Querier, pin *types.VersionPin) error {
	const sql = `INSERT INTO catalog_pins (org_id, item_id, version) VALUES ($1,$2,$3)
	             ON CONFLICT (org_id, item_id) DO UPDATE SET version = EXCLUDED.version`
	_, err := q.Exec(ctx, sql, pin.OrgID, pin.ItemID, pin.Version)
	return err
}

func (s *Store) DeletePin(ctx context.Context, q db.Querier, orgID, itemID string) error {
	_, err := q.Exec(ctx, `DELETE FROM catalog_pins WHERE org_id = $1 AND item_id = $2`, orgID, itemID)
	return err
}

func (s *Store) GetPin(ctx context.Context, q db.Querier, orgID, itemID string) (string, error) {
	var v string
	err := q.QueryRow(ctx, `SELECT version FROM catalog_pins WHERE org_id = $1 AND item_id = $2`, orgID, itemID).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func nullJSON(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}
