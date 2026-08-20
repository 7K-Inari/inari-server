// ClusterSets: label-selector cluster grouping — the targeting unit for all
// fleet operations (plan §5.11). Moved out of the policy service at M4; the
// table, events and FGA model are unchanged.
package fleetmanager

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
			return nil, fmt.Errorf("fleetmanager: cluster set selector: %w", err)
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
	cs, err := scanClusterSet(q.QueryRow(ctx, `SELECT `+clusterSetCols+` FROM cluster_sets WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return cs, err
}

func (s *Store) ListClusterSets(ctx context.Context, q db.Querier, orgID string) ([]types.ClusterSet, error) {
	rows, err := q.Query(ctx, `SELECT `+clusterSetCols+` FROM cluster_sets WHERE org_id = $1 ORDER BY created_at`, orgID)
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
	tag, err := q.Exec(ctx, `DELETE FROM cluster_sets WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
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
		return nil, ErrNotFound
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
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "cluster_set.deleted", ObjectType: "cluster_set", ObjectID: id,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventClusterSetDeleted, types.ClusterSetPayload{
			OrgID: orgID, ClusterSetID: id,
		})
	})
}

// MatchesSelector reports whether labels contain every selector pair
// (subset match).
func MatchesSelector(labels, selector map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// ResolveClusters returns the org's clusters matching the selector.
func (s *Service) ResolveClusters(ctx context.Context, orgID string, selector map[string]string) ([]types.Cluster, error) {
	all, err := s.clusters.ListClusters(ctx, orgID)
	if err != nil {
		return nil, err
	}
	var out []types.Cluster
	for _, c := range all {
		if MatchesSelector(c.Labels, selector) {
			out = append(out, c)
		}
	}
	return out, nil
}

// ClusterSetMembers resolves one set's member clusters.
func (s *Service) ClusterSetMembers(ctx context.Context, orgID, setID string) ([]types.Cluster, error) {
	cs, err := s.GetClusterSet(ctx, orgID, setID)
	if err != nil {
		return nil, err
	}
	return s.ResolveClusters(ctx, orgID, cs.LabelSelector)
}
