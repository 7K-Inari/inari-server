# ADR 0002: Database migrations — goose

## Status
Accepted (M0)

## Context
PostgreSQL schema must be versioned and applied at startup by the single binary.

## Decision
Use **goose** with plain SQL migrations embedded via `embed.FS` (`internal/db/migrations`), applied by `db.Migrate` at boot.

## Alternatives considered
- **golang-migrate**: comparable; goose's Go-first embedding and explicit Up/Down SQL fit the single-binary modular monolith better.

## Consequences
- Migrations run inside the server process (safe for the M0 single instance); if replicas ever race, move to a job/initContainer.
- Append-only `audit_events` is enforced by a trigger created in migration 0001.
