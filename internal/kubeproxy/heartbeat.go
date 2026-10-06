package kubeproxy

import (
	"context"
	"fmt"
	"time"

	"github.com/7K-Inari/inari-server/internal/db"
)

// HeartbeatWriter records tunnel-agent liveness (migration 0030). One row
// per cluster; kubeproxy upserts on stream connect, refreshes on
// (throttled) pings, and deletes on clean disconnect. The control plane's
// access-info endpoint reads the row through LivenessReader.
type HeartbeatWriter struct {
	q        db.Querier
	instance string
}

// NewHeartbeatWriter builds a writer tagging rows with the kubeproxy
// instance (hostname/pod name) holding the session.
func NewHeartbeatWriter(q db.Querier, instance string) *HeartbeatWriter {
	return &HeartbeatWriter{q: q, instance: instance}
}

// Connected upserts the cluster's row on tunnel-stream admission.
func (w *HeartbeatWriter) Connected(ctx context.Context, clusterID string) error {
	const sql = `INSERT INTO cluster_tunnel_heartbeats (cluster_id, kubeproxy_instance, connected_at, last_seen_at)
	             VALUES ($1,$2,now(),now())
	             ON CONFLICT (cluster_id) DO UPDATE
	             SET kubeproxy_instance = EXCLUDED.kubeproxy_instance,
	                 connected_at = EXCLUDED.connected_at,
	                 last_seen_at = EXCLUDED.last_seen_at`
	_, err := w.q.Exec(ctx, sql, clusterID, w.instance)
	return err
}

// Seen refreshes last_seen_at (throttled by the caller).
func (w *HeartbeatWriter) Seen(ctx context.Context, clusterID string) error {
	const sql = `UPDATE cluster_tunnel_heartbeats SET last_seen_at = now() WHERE cluster_id = $1`
	_, err := w.q.Exec(ctx, sql, clusterID)
	return err
}

// Disconnected refreshes last_seen_at on clean stream teardown rather than
// deleting the row: agents rotate sessions seconds apart (token-expiry
// rotation), and deleting made access-info flap tunnelAvailable=false in the
// reconnect gap. True teardown is indistinguishable from a crash anyway —
// the reader's freshness window expires the row either way.
func (w *HeartbeatWriter) Disconnected(ctx context.Context, clusterID string) error {
	const sql = `UPDATE cluster_tunnel_heartbeats SET last_seen_at = now() WHERE cluster_id = $1`
	_, err := w.q.Exec(ctx, sql, clusterID)
	return err
}

// DefaultTunnelFreshness bounds how stale a heartbeat row may be before the
// tunnel is reported unavailable (45s ≈ 3× the agent ping interval).
const DefaultTunnelFreshness = 45 * time.Second

// LivenessReader reports tunnel-agent availability to the control plane.
type LivenessReader struct {
	q         db.Querier
	freshness time.Duration
}

// NewLivenessReader builds a reader with the given freshness window
// (DefaultTunnelFreshness when <= 0).
func NewLivenessReader(q db.Querier, freshness time.Duration) *LivenessReader {
	if freshness <= 0 {
		freshness = DefaultTunnelFreshness
	}
	return &LivenessReader{q: q, freshness: freshness}
}

// Available reports whether a live tunnel-agent session exists for the
// cluster (fresh heartbeat row present).
func (r *LivenessReader) Available(ctx context.Context, clusterID string) (bool, error) {
	if r.q == nil {
		return false, nil
	}
	const sql = `SELECT EXISTS(
		SELECT 1 FROM cluster_tunnel_heartbeats
		WHERE cluster_id = $1 AND last_seen_at > now() - $2::interval)`
	var ok bool
	err := r.q.QueryRow(ctx, sql, clusterID, r.freshness.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("kubeproxy: tunnel liveness: %w", err)
	}
	return ok, nil
}
