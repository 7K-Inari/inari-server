# ADR 0010: Cross-replica migration serialization via Postgres session advisory lock

## Status
Accepted

## Context
Every inari-server replica applies goose migrations at boot (`db.Migrate`,
invoked from `cmd/inari-server/main.go`). ADR 0002 noted this was safe only
for the M0 single instance: with `replicaCount >= 2`, simultaneous first
boots against a fresh database interleave DDL and one racer fails
(`duplicate key value violates unique constraint`, `relation already
exists`), crash-looping that replica. This blocks running 2+ replicas for the
99.9% availability initiative.

## Decision
Serialize migrations in-process with goose v3's
`lock.NewPostgresSessionLocker` (PostgreSQL session-level
`pg_try_advisory_lock`, lock ID `lock.DefaultLockID`) wired through
`goose.NewProvider(..., goose.WithSessionLocker(...))` in `db.Migrate`.

- Non-holders **wait** (bounded retry, 5s probes) instead of failing; once
  the holder finishes, waiters see no pending migrations and boot normally.
- The wait is bounded by `db.DefaultLockWaitTimeout` (60s); a replica that
  cannot acquire the lock in time fails fast with an error naming the
  migration lock, and acquisition/timeout is logged via `slog`.
- Session-level locks self-release when the holder's connection dies, so a
  crashed replica cannot wedge subsequent boots.

## Alternatives considered
- **Helm migrate hook / initContainer job**: serializes via orchestration,
  but adds a moving part to every deploy (hook ordering, hook cleanup
  policies, RBAC for a separate pod) and splits schema ownership out of the
  binary. Rejected to keep zero-extra-moving-parts boot; the in-process lock
  covers both fresh-boot races and rolling-upgrade overlaps.
- **goose table-based locker** (`NewPostgresTableLocker`): survives nothing
  the session locker doesn't, adds a heartbeat goroutine + lease table, and a
  crashed holder blocks others until the 30s lease expires. Strictly worse.
- **Hand-rolled `pg_advisory_lock` around `goose.UpContext`**: re-implements
  retry/timeout/release logic goose already ships and tests.

## Consequences
- `db.Migrate` switched from the legacy global `goose.UpContext` API to the
  Provider API; behavior for the single-replica path is unchanged beyond lock
  acquire/release (uncontended acquisition succeeds on the first probe).
- Supersedes the ADR 0002 note "if replicas ever race, move to a
  job/initContainer" — the race arrived and was closed in-process instead.
- Regression coverage: `internal/db/migrate_integration_test.go`
  (`TestMigrateConcurrentFreshBoot` 0→2 concurrent first boot,
  `TestMigrateLockWaitTimeout` bounded fail-fast under a pinned lock).
