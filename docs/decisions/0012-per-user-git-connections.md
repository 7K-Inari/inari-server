# ADR-0012: Per-User Git Connections (User Git Social Login)

Status: Accepted (W4)

## Context

User-attributed git operations (W5 resolver model C, scaffold routing) need a
short-lived access token minted on behalf of the *calling user*, not the
platform or a tenant BYO GitHub App. This requires a per-user OAuth
connection whose refresh token the control plane stores durably and whose
access tokens it mints on demand.

## Decision

1. **Dedicated GitHub App user OAuth flow.** A separate GitHub App (client
   id + mounted client secret, `INARI_USERGIT_GITHUB_*`) issues expiring
   user-to-server tokens with refresh-token rotation. It is distinct from
   the platform app and tenant BYO apps (installation tokens, ADR-0010):
   different token semantics, different compromise blast radius. GitLab and
   Forgejo sit behind the same `usergit.Provider` interface as planned
   (501) implementations.

2. **Envelope encryption with a KEK backend seam.** Only the refresh token
   is persisted (`user_git_connections.refresh_token_enc`, per-row
   AES-256-GCM DEK, AAD `user_git_connections:<row id>`). DEK wrapping goes
   through a `KEK` interface: `StaticKEK` (AES-256-GCM key file, dev
   default, sharing the `INARI_CREDENTIAL_KEK_FILE` fallback with the W3
   credential vault) or `TransitKEK` (OpenBao/Vault transit,
   `INARI_USERGIT_KEK_BACKEND=transit`). Access tokens are cached in memory
   only — never in the database. Key and token material never appear in
   logs, errors, audit payloads, or REST responses.

3. **Stateless signed OAuth state + in-memory single-use nonce.** The
   `state` parameter is an HMAC-SHA256-signed payload binding
   (org, user sub, provider, apiBase, PKCE verifier) with a 10-minute TTL;
   a per-process nonce table makes each state single-use. **Limitation:**
   multi-replica deployments can strand in-flight flows when the callback
   lands on another pod — the failure mode is a safe re-auth, never a
   bypass. A shared nonce store (Redis) or sticky sessions is a follow-up
   when the control plane runs multi-replica.

4. **Rotation with persist-before-use and compromise wipe.** Refreshes are
   single-flighted per connection. A rotated refresh token is re-encrypted
   and persisted *before* the new access token is handed out. A
   provider-rejected refresh token (rotated away / revoked / replayed) is
   treated as compromise: the connection row is wiped, a
   `user_git.compromised` audit + outbox event is emitted, and the caller
   gets `ErrConnectionCompromised`. Fail closed: a rejected refresh token
   is never retried.

5. **Self-service, tenant-scoped REST.** Routes live under
   `/api/v1/tenants/{org}/git-connections[...]`, registered only via
   `restsurface.Register`. Any org member (viewer relation) manages their
   *own* connections; the user identity is always the JWT subject, never
   request input. Disconnect revokes the provider grant (best-effort) and
   deletes the row after decrypt-first verification (same discipline as the
   W3 credential vault). GHE/self-hosted API bases are restricted to an
   explicit allowlist (`INARI_USERGIT_API_BASE_ALLOWLIST`, https only).

## Consequences

- W5 consumes `usergit.Service.AccessToken(ctx, orgID, userSub, provider)`
  through a narrow consumer interface; the git resolver itself is
  untouched in W4.
- The compromise-wipe policy means a benign race (two control-plane
  processes refreshing the same connection concurrently without the
  single-flight, e.g. after a cache flush on one replica) can wipe a
  healthy connection; the user simply re-connects. We accept this over
  silently tolerating replay.
- No new migrations: the W3 schema (migration 0028) already carries the
  table; state nonces deliberately avoid a DB table for the same reason.
