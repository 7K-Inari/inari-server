-- +goose Up
-- Multi-replica safety (ADR-0011): DB-backed leader leases so exactly one
-- replica drives each singleton background loop. All expiry math uses the
-- DB clock (now()) so replicas need no clock-skew handling.
CREATE TABLE leader_leases (
    name        TEXT PRIMARY KEY,
    holder      TEXT NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS leader_leases;
