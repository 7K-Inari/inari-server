# ADR 0016: Actor-free service tenant provisioning

## Status

Accepted (BIL-1)

## Context

The interactive tenant lifecycle uses one subject for two purposes: audit
attribution and creator membership. Reusing it for a provisioning service would
make that service account an administrator/member of every tenant it creates.
Conversely, creating only Keycloak objects would skip the server DB projection,
roles, default teams, OpenFGA bootstrap outbox, base platform resources, and
kubectl client.

The original create flow is also intentionally strict: a Keycloak Organization
followed by a DB failure may produce an alias conflict on retry.

## Decision

Preserve `CreateTenant` as the interactive wrapper and add `ProvisionTenant` as
an actor-free ensure lifecycle. The shared implementation distinguishes `actor`
(audit attribution) from `creatorUserID` (optional human membership). An empty
creator skips every organization, group, DB-membership, and membership-outbox
write for the caller.

The existing `POST /api/v1/tenants` operation selects this path only for an
exactly configured OAuth client ID (`azp`) and service-account subject (`sub`)
pair carrying the `provisioning` scope. Both service and interactive callers
must still pass `platform:inari org_creator`; scope never replaces OpenFGA.
`INARI_TENANT_PROVISIONING_IDENTITIES` contains comma-separated
`client-id:service-account-subject` pairs and is empty by default.

`ProvisionTenant` is replayable:

- An existing DB projection is returned after ensuring groups, base resources,
  and kubectl client, without repeating bootstrap records.
- `OrganizationEnsurer` resolves a create conflict through an exact alias read
  so a post-Keycloak/pre-DB crash can resume.
- A unique-slug race reloads the winner and never deletes its Organization.
- The ensure path retains partial external state for a later retry instead of
  applying the interactive compensation delete.

The REST request, response, operation ID, and OpenAPI route set remain
unchanged. Service identities must be dedicated clients with user flows
disabled; their subjects remain audit actors, not tenant users.

## Consequences

- The full existing lifecycle is reused without granting a provisioning
  service account tenant-admin membership.
- Keyed callers can safely replay after failures at external/DB boundaries.
- Interactive creation retains its existing strict conflict and creator
  behavior.
- Disabled or malformed service-identity configuration cannot select the
  actor-free path, and no new commercial API is mounted in the public server.
