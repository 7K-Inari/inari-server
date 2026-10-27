-- +goose Up
-- One git repo (case-insensitive slug + provider) lives in at most one
-- org: webhook deliveries (0038) are routed to a single row by
-- (lower(repo), provider) and verified with that row's HMAC secret — a
-- second org holding the same slug would route its deliveries to the
-- wrong secret and deterministically 401 (GitHub eventually disables the
-- hook). gitrepos.Register rejects this with ErrRepoRegisteredElsewhere;
-- this index is the race backstop for every writer (Register, TZF
-- baseline upsert, legacy git-config mirror). It also subsumes same-org
-- case-variant duplicates, which UNIQUE(org_id, repo) missed.
CREATE UNIQUE INDEX tenant_git_repos_repo_provider_key
    ON tenant_git_repos (lower(repo), provider);

-- +goose Down
DROP INDEX IF EXISTS tenant_git_repos_repo_provider_key;
