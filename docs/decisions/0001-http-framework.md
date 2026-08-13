# ADR 0001: HTTP framework — Huma v2 on chi

## Status
Accepted (M0)

## Context
The REST API must be OpenAPI-described with codegen (AGENTS.md stack). Long-term the OpenAPI specs live in `inari-api` (spec-first, §6), but that repo has not tagged v0.1.0 yet.

## Decision
Use **Huma v2** on chi: OpenAPI is generated from Go handler registrations, so the spec can never drift from the implementation. Business logic stays in module services behind interfaces; Huma handlers are thin adapters, so migrating to spec-first codegen (oapi-codegen from `inari-api`) later only rewrites the HTTP layer.

## Alternatives considered
- **chi + oapi-codegen (spec-first)**: matches the end state, but doubles maintenance while contracts are unstable at M0.
- **Plain chi**: no codegen, spec drift.

## Consequences
- Handler-level coupling to Huma; contained by the interface-first module rule.
- Swagger UI / OpenAPI JSON available out of the box at `/openapi.json` and `/docs`.
