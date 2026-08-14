# inari-server

Control plane for Inari: REST API/BFF, agent gRPC gateway, tenancy & identity, cluster registry, catalog service, orchestrator, cloud accounts, resources inventory, audit, approvals, notifications, extension host, fleet manager, policy service, tenant zone factory (plan §5.2).

Stack: Go, PostgreSQL, chi/Huma (REST/OpenAPI codegen), gRPC (agent gateway), NATS (event bus), OpenFGA (authz)

Part of the **Inari** multi-tenant Internal Developer Platform (GitHub org `7K-Inari`).
Canonical architecture & development plan: [inari-docs/docs/architecture/inari-platform-plan.md](https://github.com/7K-Inari/inari-docs/blob/main/docs/architecture/inari-platform-plan.md)

## Development

```sh
# Start dev dependencies (PostgreSQL, Keycloak with imported `inari` realm, OpenFGA)
docker compose -f docker-compose.dev.yaml up -d

# Run the server (config via INARI_* env vars, see internal/config)
make run

# Unit tests / integration tests (testcontainers; requires Docker)
make test
make test-integration

# Lint / container image
make lint
make docker
```

Dev realm (`deploy/dev/keycloak/inari-realm.json`) ships user `dev-admin` / `dev-admin` and public client `inari-server` with the `organization` scope. Get a token:

```sh
curl -s http://localhost:8081/realms/inari/protocol/openid-connect/token \
  -d grant_type=password -d client_id=inari-server \
  -d username=dev-admin -d password=dev-admin -d scope=openid | jq -r .access_token
```

Module boundaries: everything under `internal/<module>` is reachable only through its exported service interfaces; wiring lives in `cmd/inari-server/main.go`. Contract types are local (`internal/types`) until `inari-api` tags v0.1.0.
