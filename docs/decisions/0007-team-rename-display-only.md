# ADR-0007: Team rename is display-name only; policy updates keep exemption bindings

Status: accepted
Date: 2026-09-13

## Context

The live e2e run (task 716c6404) found two CRUD holes:

1. `PUT /api/v1/tenants/{org}/policies/{id}` accepted only `{source, enabled}` —
   a policy's name or target could not be changed without delete+recreate,
   and there was no org-scoped name uniqueness, so renames had no
   well-defined conflict behavior.
2. `PUT /api/v1/tenants/{org}/teams/{team}` did not exist — teams had
   create/delete only, so there was no rename path at all.

## Decisions

### Policy updates

- `PUT /policies/{id}` now accepts optional `name` and `target` alongside
  `source`/`enabled`; empty values keep the current field. Every update
  bumps `version` and is audited (`policy.updated`).
- A new unique index `policies_org_name_key` on
  `policies (COALESCE(org_id, ''), name)` enforces org-scoped name
  uniqueness (including platform-global rows); a conflicting rename returns
  `ErrPolicyNameTaken` → **409**.
- Rego source is compiled before persisting (invalid source → 422), same
  as create. Policies remain rego-only; CEL exists solely as the `cel-vap`
  policy-*pack* engine.
- **Exemption semantics:** exemptions reference the stable policy ID
  (`policy:<uuid>`), never the name. Renames, retargets, and source edits
  therefore **cannot break exemptions** — an approved, unexpired exemption
  keeps exempting the policy's violations across updates. Source edits take
  effect at the next evaluation; `enabled=false` stops enforcement
  immediately. Only delete+recreate broke the binding, and the update route
  removes the need for it.

### Team rename = display name only

- Teams gain a mutable `display_name` column, editable via
  `PUT /tenants/{org}/teams/{team}` (org-admin gated, audited
  `team.updated`).
- The team `name` (URL identifier) and `keycloak_group_path` are
  **immutable**. The Keycloak group path backs the brokered IdP Hardcoded
  Group mapper (ADR-0004), token group claims, and the OpenFGA team tuples
  (keyed by the stable team UUID); renaming it would require a Keycloak
  group rename plus FGA re-sync for no consumer benefit. Because no FGA
  tuple changes, the update writes no outbox event.
- Default/anchor teams (`org-admins`, `platform-team`, `developers`,
  `viewers`) reject updates with `ErrDefaultTeam` → **409**, exactly
  mirroring the delete protection.

## Coordination

Sibling task e75d3729's policy-pack surfaces (`DELETE /policy-packs/{id}`
with `force`, `GET /policy-packs/{id}/assignments`) are already merged;
this change adds no pack routes, so the surfaces do not conflict. A future
"pack update/distribution status" surface belongs to the pack lifecycle
scope, not to this CRUD work.
