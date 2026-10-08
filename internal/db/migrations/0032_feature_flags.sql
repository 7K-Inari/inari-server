-- +goose Up
-- Runtime feature flags (kill-switch v2, ADR-0014 addendum): platform-scoped
-- defaults plus per-cluster overrides, written via the feature-flags REST
-- API and read through the OpenFeature DB provider by inari-server and
-- inari-kubeproxy. No rows needed on upgrade: absent rows fall back to the
-- flag's built-in default from internal/featureflags/registry.go.
CREATE TABLE feature_flags (
    flag_key   text        NOT NULL,
    scope      text        NOT NULL CHECK (scope IN ('platform', 'cluster')),
    scope_key  text        NOT NULL DEFAULT '', -- cluster id when scope='cluster'
    value      jsonb       NOT NULL,
    updated_by text        NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (flag_key, scope, scope_key)
);

-- +goose Down
DROP TABLE feature_flags;
