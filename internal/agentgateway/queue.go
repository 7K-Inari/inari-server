package agentgateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Queue is the durable per-agent command queue backing at-least-once
// delivery (plan §5.2). Command IDs are idempotency keys; a command leaves
// the queue only via an explicit ack/nack from the agent.
type Queue struct {
	db         *db.DB
	retryAfter time.Duration
	now        func() time.Time
}

func NewQueue(d *db.DB, retryAfter time.Duration) *Queue {
	if retryAfter <= 0 {
		retryAfter = 30 * time.Second
	}
	return &Queue{db: d, retryAfter: retryAfter, now: time.Now}
}

// Enqueue inserts a command. Payload is protojson of the google.protobuf.Any
// wrapping the concrete command message.
func (q *Queue) Enqueue(ctx context.Context, cmd *types.AgentCommand) error {
	const sql = `INSERT INTO agent_commands (id, cluster_id, type, payload)
	             VALUES ($1,$2,$3,$4)
	             ON CONFLICT (id) DO NOTHING
	             RETURNING created_at, updated_at`
	err := q.db.Pool.QueryRow(ctx, sql, cmd.ID, cmd.ClusterID, cmd.Type, cmd.Payload).
		Scan(&cmd.CreatedAt, &cmd.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // idempotent re-enqueue
	}
	return err
}

// Due returns commands to (re)deliver: never sent, or delivered but unacked
// past the retry window.
func (q *Queue) Due(ctx context.Context, clusterID string, limit int) ([]types.AgentCommand, error) {
	if limit <= 0 {
		limit = 50
	}
	const sql = `SELECT id, cluster_id, type, payload, status, attempts, result_message, created_at, updated_at
	             FROM agent_commands
	             WHERE cluster_id = $1 AND (
	               status = 'pending' OR
	               (status = 'delivered' AND updated_at < $2)
	             )
	             ORDER BY created_at LIMIT $3`
	rows, err := q.db.Pool.Query(ctx, sql, clusterID, q.now().Add(-q.retryAfter), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.AgentCommand
	for rows.Next() {
		var c types.AgentCommand
		if err := rows.Scan(&c.ID, &c.ClusterID, &c.Type, &c.Payload, &c.Status,
			&c.Attempts, &c.ResultMessage, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// MarkDelivered records a send attempt.
func (q *Queue) MarkDelivered(ctx context.Context, id string) error {
	const sql = `UPDATE agent_commands SET status = 'delivered', attempts = attempts + 1, updated_at = now()
	             WHERE id = $1 AND status IN ('pending', 'delivered')`
	_, err := q.db.Pool.Exec(ctx, sql, id)
	return err
}

// Complete records the agent's ack/nack; the command leaves the queue.
func (q *Queue) Complete(ctx context.Context, id string, status types.CommandStatus, message string) error {
	if status != types.CommandStatusAcked && status != types.CommandStatusNacked {
		return fmt.Errorf("agentgateway: invalid terminal status %q", status)
	}
	const sql = `UPDATE agent_commands SET status = $2, result_message = $3, updated_at = now() WHERE id = $1`
	_, err := q.db.Pool.Exec(ctx, sql, id, status, message)
	return err
}
