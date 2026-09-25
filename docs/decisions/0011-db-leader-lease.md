# ADR 0011: DB-backed leader lease for singleton loops, and agent-session fencing

(ADR-0010, the hybrid git-provider model, lives in inari-docs.)

## Status
Accepted

## Context
The 99.9% availability initiative runs inari-server with `replicaCount=2`.
Eight background loops were started uncoordinated in `cmd/inari-server`
(platform/team group syncs, catalog OCI sync, approvals expiry,
tenant-deletion resume, fleet advance/drift, TZF reconcile), so every replica
drove each loop. Verification of double-run effects found two unsafe loops:
the TZF reconcile loop has no row locking (`ResumeZone` can run concurrently
against the same zone — duplicate git commits / AWS calls / audit events),
and the fleet drift sweep does check-then-insert on drift events with no
unique constraint (duplicate events → duplicate audit/outbox → duplicate
notifications). The rest are idempotent but still better run once.

Additionally, `agentgateway.Connect` created an independent session per bidi
stream with no guard against two live sessions for the same cluster identity,
and the command queue's `Due` is an unclaimed SELECT — duplicate sessions
double-dispatch commands. The inari-agent active-passive failover path
therefore depended on races.

A Kubernetes `Lease` was not an option: the control plane has no k8s API
client/RBAC (pull-never-push, §5.10).

## Decision
- New `internal/leaderlease` module: a small `Leaser`/`Lease` interface
  (acquire/renew/release, no pgx types) backed by a `leader_leases` table
  (migration 0026). Acquire is an
  `INSERT ... ON CONFLICT DO UPDATE ... WHERE expires_at < now()`; renew is a
  holder-scoped `UPDATE`; release a holder-scoped `DELETE`. All expiry math
  uses the DB clock, so replicas need no clock-skew handling. A renewal miss
  (or renewal failure lasting past the TTL) closes `Lease.Done()`; the
  `leaderlease.Run` helper cancels the loop's context, releases, and
  re-acquires. Failover is bounded by the TTL (`INARI_LEADER_LEASE_TTL`,
  default 10s); non-leaders idle in the acquire retry loop.
  A Postgres session advisory lock was considered and rejected: leadership-
  loss detection would need an active probe on a pinned connection, and
  release depends on TCP teardown that can linger behind LBs — the table's
  TTL gives deterministic, observable failover instead.
- All eight loops are wrapped in `leaderlease.Run` in `cmd/inari-server`.
  The tenant-deletion resume is a one-shot scan: it runs once per lease
  acquisition (failover re-scans crashed teardowns) and the leader then
  holds the lease idle. Claim-based `SKIP LOCKED` loops (outbox dispatcher,
  scaffold reconcile) are already multi-replica safe and stay ungated.
- `internal/agentgateway` gains a per-cluster session registry: a new stream
  for an already-connected cluster deterministically evicts (cancels) the
  stale session — last-writer-wins, logged with old/new session ids. A late
  unregister from an evicted session never removes its replacement.

## Consequences
- Each replica runs a cheap acquire/renew query per lease (8 leases, ~1
  write per TTL/3 per lease on the leader only) — negligible load.
- A DB outage longer than the TTL stops all gated loops on all replicas;
  exactly one re-acquires on recovery. During that window the loops' work
  is deferred, not duplicated.
- The agent gateway keeps at most one session per cluster per replica;
  cross-replica duplicates are still possible only while both server pods
  accept streams for the same cluster, which the eviction makes
  self-healing (each new stream wins; the agent's reconnect converges).
