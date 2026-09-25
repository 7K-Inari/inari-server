# ADR 0009: Server-side catalog filtering, sorting, and pagination

## Status
Accepted

## Context
The catalog browse page offered only a client-side source toggle: no search,
no sorting, no pagination, no cluster-compatibility filter, and filter state
was lost on navigation. The platform plan (§8.2) specifies browse filters for
cluster compatibility, category, and source. Two personas use the page:
developers discovering "what can I run on my cluster?" and platform engineers
curating what tenants see.

`package.yaml` already declares a `category`, but the OCI sync parsed and
dropped it, so no category facet could exist. Discovered capabilities are
projected in Go at request time (never persisted), so they have no category
column and no stored `created_at`.

## Decision
The browse endpoint `GET /api/v1/tenants/{org}/catalog` gains whitelisted
query params: `q` (free text over name/display name/description), `source`,
`category`, `sort` (`name`, `name-desc`, `newest`, `oldest`), `limit`,
`offset` — plus the existing `cluster`. The response body gains `total`
(count before pagination).

- **Persisted items** are filtered and sorted in SQL. Sort values map to
  ORDER BY clauses through a server-side whitelist — client input is never
  interpolated into SQL.
- **Discovered projections** (present only when `cluster` is set) are
  filtered with the same facet semantics in Go, merged with the persisted
  set, and the merged list is sorted and sliced, so ordering and pagination
  stay correct across both kinds. Discovered items have no category: a
  category filter excludes them. Their `createdAt` is the capability's
  FirstSeenAt; zero times sort last under `newest`.
- **Category** is persisted on `catalog_items` (migration 0025) from
  `package.yaml` / fixture `metadata.json` during sync.

Client-side filtering in inari-ui is removed; filter state lives in the URL
(ADR-0008 in inari-docs deep-link principles), making filtered views
shareable.

## Consequences
- The OpenAPI contract changes; inari-ui must re-pin (`npm run sync:api`)
  before its next release (contract-gate).
- Pagination runs after the in-memory merge, so the filtered persisted set is
  loaded fully. Acceptable at current catalog sizes; a future facet-count /
  FTS iteration can move pagination into SQL when discovered projections are
  excluded.
- Unknown/future categories and sources remain forward-compatible: facets are
  free-form strings, only `sort` and `source` are enum-validated.
