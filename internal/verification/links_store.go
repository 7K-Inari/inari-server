package verification

import (
	"context"
	"errors"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/jackc/pgx/v5"
)

func (s *Store) GetLatestAttempt(ctx context.Context, q db.Querier, runID string, attempt int) (*RunAttempt, error) {
	var out RunAttempt
	err := q.QueryRow(ctx, `SELECT run_id, attempt, workflow_name, workflow_namespace, workflow_uid, cluster_id, links_expire_at
		FROM verification_run_attempts WHERE run_id=$1 AND attempt=$2`, runID, attempt).Scan(
		&out.RunID, &out.Attempt, &out.WorkflowName, &out.WorkflowNamespace, &out.WorkflowUID, &out.ClusterID, &out.LinksExpireAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &out, err
}
