package secretstores

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrNotFound is returned when a secret store does not exist.
var ErrNotFound = errors.New("secretstores: not found")

// ErrInvalidInput is returned for malformed requests.
var ErrInvalidInput = errors.New("secretstores: invalid input")

// ErrConflict is returned when a store name is already taken in the org.
var ErrConflict = errors.New("secretstores: name already exists")

// Store is the PostgreSQL projection of the SecretStore registry.
type Store struct{}

func NewStore() *Store { return &Store{} }

const storeCols = `id, org_id, name, scope, targets, provider, created_at, updated_at`

func scanStore(row pgx.Row) (*types.SecretStore, error) {
	var st types.SecretStore
	var targets, provider []byte
	err := row.Scan(&st.ID, &st.OrgID, &st.Name, &st.Scope, &targets, &provider, &st.CreatedAt, &st.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(targets, &st.Targets); err != nil {
		return nil, fmt.Errorf("secretstores: targets: %w", err)
	}
	if err := json.Unmarshal(provider, &st.Provider); err != nil {
		return nil, fmt.Errorf("secretstores: provider: %w", err)
	}
	return &st, nil
}

func (s *Store) Create(ctx context.Context, q db.Querier, st *types.SecretStore) error {
	targets, err := json.Marshal(st.Targets)
	if err != nil {
		return err
	}
	provider, err := json.Marshal(st.Provider)
	if err != nil {
		return err
	}
	const sql = `INSERT INTO secret_stores (id, org_id, name, scope, targets, provider)
	             VALUES ($1,$2,$3,$4,$5,$6) RETURNING ` + storeCols
	out, err := scanStore(q.QueryRow(ctx, sql, st.ID, st.OrgID, st.Name, st.Scope, targets, provider))
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	*st = *out
	return nil
}

func (s *Store) Update(ctx context.Context, q db.Querier, st *types.SecretStore) error {
	targets, err := json.Marshal(st.Targets)
	if err != nil {
		return err
	}
	provider, err := json.Marshal(st.Provider)
	if err != nil {
		return err
	}
	const sql = `UPDATE secret_stores SET targets = $3, provider = $4, updated_at = now()
	             WHERE org_id = $1 AND name = $2 RETURNING ` + storeCols
	out, err := scanStore(q.QueryRow(ctx, sql, st.OrgID, st.Name, targets, provider))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	*st = *out
	return nil
}

// Get returns one store by name. Platform-scoped stores are visible to any
// org (read-only for tenants); cluster-scoped stores are org-owned.
func (s *Store) Get(ctx context.Context, q db.Querier, orgID, name string) (*types.SecretStore, error) {
	const sql = `SELECT ` + storeCols + ` FROM secret_stores
	             WHERE name = $1 AND (org_id = $2 OR scope = 'platform')`
	st, err := scanStore(q.QueryRow(ctx, sql, name, orgID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return st, err
}

// List returns the org's cluster-scoped stores plus all platform-scoped
// stores (tenant read-only view of the platform registry).
func (s *Store) List(ctx context.Context, q db.Querier, orgID string) ([]types.SecretStore, error) {
	const sql = `SELECT ` + storeCols + ` FROM secret_stores
	             WHERE org_id = $1 OR scope = 'platform' ORDER BY scope, name`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.SecretStore
	for rows.Next() {
		st, err := scanStore(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *st)
	}
	return out, rows.Err()
}

// Delete removes one store row by ID. Ownership/scope checks happen in the
// service before this is called.
func (s *Store) Delete(ctx context.Context, q db.Querier, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM secret_stores WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// commandState is one agent-reported command outcome for the status
// projection.
type commandState struct {
	ClusterID string
	Status    types.CommandStatus
	Message   string
}

// CommandStates returns the latest command outcome per cluster for one
// store. Each mutation enqueues a fresh command ID (nonce-suffixed), so a
// cluster may have several rows; only the newest reflects current delivery.
func (s *Store) CommandStates(ctx context.Context, q db.Querier, storeID string) ([]commandState, error) {
	const sql = `SELECT DISTINCT ON (cluster_id) cluster_id, status, result_message
	             FROM agent_commands
	             WHERE id LIKE 'secretstore:' || $1 || ':%'
	             ORDER BY cluster_id, created_at DESC`
	rows, err := q.Query(ctx, sql, storeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []commandState
	for rows.Next() {
		var cs commandState
		if err := rows.Scan(&cs.ClusterID, &cs.Status, &cs.Message); err != nil {
			return nil, err
		}
		out = append(out, cs)
	}
	return out, rows.Err()
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
