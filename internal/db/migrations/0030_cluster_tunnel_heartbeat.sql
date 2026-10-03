-- +goose Up
-- Kubectl gateway (plan §7.2): inari-kubeproxy records tunnel-agent liveness
-- here; the control plane (clusterregistry access-info) reads it to report
-- tunnelAvailable. One row per cluster — a tunnel-agent session is fenced
-- last-writer-wins per cluster, so a single upserted row suffices. Distinct
-- from clusters.last_seen_at, which tracks the control-plane inari-agent.
CREATE TABLE cluster_tunnel_heartbeats (
    cluster_id          TEXT PRIMARY KEY REFERENCES clusters(id) ON DELETE CASCADE,
    kubeproxy_instance  TEXT NOT NULL DEFAULT '',
    connected_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE cluster_tunnel_heartbeats;
