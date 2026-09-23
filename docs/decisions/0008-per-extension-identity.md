# ADR 0008: Per-extension identity for the extension-gateway tunnel

## Status
Accepted

## Context
The extension-gateway tunnel (`/inari.extensions.v1.AgentGateway/InvokeAction`)
lets extension backends run imperative actions on tenant clusters. It shipped
with an interim gate: one shared static token
(`INARI_EXTENSION_GATEWAY_TOKEN`, presented in the `x-inari-extension-token`
header) which, in the e2e environment, was the `inari-keycloak-admin` client
secret (issue #75). Any extension compromise therefore exposed the Keycloak
**admin** client credentials, and every extension authenticated as the same
principal — no per-extension revocation, rotation, or audit attribution.

## Decision
Each backend extension gets a **dedicated Keycloak service-account client**,
and the tunnel authenticates callers with standard OIDC JWTs:

- **Provisioning.** `extensionhost.Service.Register` (and `Verify` lazily for
  pre-existing rows) creates a confidential client `ext-<name>`
  (`serviceAccountsEnabled`, no flows, no redirect URIs) via the existing
  `tenancy.KeycloakAdmin` client CRUD seam, carrying exactly one audience
  scope: `inari-extension-gateway` (`INARI_EXTENSION_GATEWAY_AUDIENCE`).
  Extension names are globally unique in the registry, so clientIds are
  collision-free. The secret is returned **exactly once** in the register
  response (`credentials`); only the `client_id` projection is persisted on
  the extension row (migration 0024). A TX failure after the Keycloak write
  best-effort disables the client (same compensation pattern as identity
  clients).
- **Authentication.** Extension backends fetch a `client_credentials` token
  from Keycloak and present it as `Authorization: Bearer` on the tunnel. The
  `extensionhost.TunnelAuthenticator` validates it with an
  `authn.OIDCValidator` pinned to the gateway audience (a token minted for
  any other purpose — user sessions, agent clients — is rejected), resolves
  the `azp` claim to the extension row via `client_id`, and requires state
  `ready`.
- **Scoping.** An org-scoped extension may only invoke within its own tenant
  (its row's `org_id` must equal `x-inari-tenant`); platform-global
  extensions stay unbound. End-user authorization is unchanged at the
  extension proxy (JWT + FGA `invoke`); no platform-admin role or org
  membership is ever granted to extension clients.
- **Rotation.** `POST /api/v1/tenants/{org}/extensions/{id}/identity/rotate`
  regenerates the secret (returned once, audited
  `extension.identity.secret_rotated`) — per-extension, independent of every
  other extension and of the platform admin client.
- **Revocation.** `Unregister` disables the Keycloak client
  (`extension.identity.disabled`); in-flight tokens expire on their short
  TTL.
- **Attribution.** Every tunneled invoke writes an
  `extension.action_invoked` audit row whose actor is the extension's own
  clientId before the command is queued.
- **Cutover.** The shared token (`INARI_EXTENSION_GATEWAY_TOKEN`,
  `x-inari-extension-token`) is removed outright — it was explicitly
  interim. Extensions obtain credentials from the register or rotate
  response.

## Consequences
- Extension compromise no longer yields Keycloak admin credentials; blast
  radius is one extension's invoke capability, revocable by disabling one
  client or the extension row.
- Extensions must store their clientId/secret themselves (they already hold
  configuration); a lost secret is recovered via the rotate route.
- The tunnel endpoint is mounted whenever the control plane can talk to
  Keycloak (no separate feature flag); deployments that never register
  backend extensions simply see no callers.
