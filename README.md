# inari-server

Control plane for Inari: REST API/BFF, agent gRPC gateway, tenancy & identity, cluster registry, catalog service, orchestrator, cloud accounts, resources inventory, audit, approvals, notifications, extension host, fleet manager, policy service, tenant zone factory (plan §5.2).

Stack: Go, PostgreSQL, chi/Huma (REST/OpenAPI codegen), gRPC (agent gateway), NATS (event bus), OpenFGA (authz)

Part of the **Inari** multi-tenant Internal Developer Platform (GitHub org `7K-Inari`).
Canonical architecture & development plan: [inari-docs/docs/architecture/inari-platform-plan.md](https://github.com/7K-Inari/inari-docs/blob/main/docs/architecture/inari-platform-plan.md)
