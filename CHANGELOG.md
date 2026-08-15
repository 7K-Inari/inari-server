# Changelog

## 1.0.0 (2026-08-15)


### Features

* **agentgateway,capabilities,authz:** Connect-RPC agent gateway, capability ingestion, cluster tuples ([7a6a7e4](https://github.com/7K-Inari/inari-server/commit/7a6a7e4b8d66f70c6a103dbc513176394ea9892b))
* **approvals:** per-item approval gating (auto/peer/platform-admin) with REST API; tenancy RoleOf ([02f263d](https://github.com/7K-Inari/inari-server/commit/02f263dfbfaaeb3c61366c7bb8b24087f59a9590))
* **audit:** append-only audit store and transactional outbox dispatcher ([147d1d8](https://github.com/7K-Inari/inari-server/commit/147d1d8cb31607d44a3ea1964a90a6aec8ebf636))
* **authn:** OIDC JWT validation middleware and coarse org-claim PEP ([39214d9](https://github.com/7K-Inari/inari-server/commit/39214d9cf5ee1a4036a6de0ca4a0f2cbbdd20d5d))
* **authz:** Authorizer interface, OpenFGA v1 model, outbox tuple writer ([4928ddc](https://github.com/7K-Inari/inari-server/commit/4928ddc7554d979f032b3c46bad3667457089053))
* **catalog,orchestrator,inventory,approvals:** M2 catalog service, deploy pipeline, resources inventory, approvals, upgrade flow ([bf60df2](https://github.com/7K-Inari/inari-server/commit/bf60df2d7f855a1156b1ca88ad295fe50724a8d1))
* **catalog:** CatalogItem model, OCI fixture sync, visibility, version pins, REST API ([4d905c6](https://github.com/7K-Inari/inari-server/commit/4d905c6e03b99d9626803d5e5e2d7084dadd8ac2))
* cluster registry, agent gateway, and release pipeline (M1 W2) ([1b91714](https://github.com/7K-Inari/inari-server/commit/1b91714ededf2f0442e9c631b9e7e1e0b4770ae0))
* **clusterregistry:** cluster records, one-time TTL'd tokens, approval and revocation ([eb3e90b](https://github.com/7K-Inari/inari-server/commit/eb3e90bb6e809a8f68934a8be5ef3bc83a503a36))
* **cmd:** wire cluster registry, capabilities, and agent gateway ([d9b0f02](https://github.com/7K-Inari/inari-server/commit/d9b0f020fa6110ff34f1be68517b84ba9d0e5361))
* **config,db:** cluster registry schema and agent gateway configuration ([d91205c](https://github.com/7K-Inari/inari-server/commit/d91205c424d706a0c91f4e5980d2833c01b7e919))
* **db,authz,types:** catalog/orchestrator schema, catalog+instance FGA types, M2 domain types ([6262baa](https://github.com/7K-Inari/inari-server/commit/6262baae9f3a9978dac03d8259f97125659f83ed))
* **db:** pgx pool, transactor, goose migrations for core schema (organizations, teams, users, memberships, audit_events, outbox) ([4dc8508](https://github.com/7K-Inari/inari-server/commit/4dc85081e913f54fb066a7743470d5961473742e))
* M0 control-plane foundations (tenancy, authn/authz, audit outbox) ([fc82725](https://github.com/7K-Inari/inari-server/commit/fc8272590b5d279be8accf2d40f76335122dac4d))
* **orchestrator,inventory:** deploy pipeline (git provider abstraction, render, argocd registration), resources inventory + gateway status-update hook ([2633e7d](https://github.com/7K-Inari/inari-server/commit/2633e7d25401ae656ac6cc40ec1a88bf9f4a0484))
* service skeleton with huma/chi, layered config, slog, health probes ([0189ae1](https://github.com/7K-Inari/inari-server/commit/0189ae1f02b31dd4166bb441493354857a3b4044))
* **tenancy:** Keycloak Organizations identity provider and tenant/team API ([14a101f](https://github.com/7K-Inari/inari-server/commit/14a101f8879fcd298b0b7946d5477e90c4bb0e75))
* **tenancy:** per-cluster Keycloak client provisioning and revocation ([dab8ade](https://github.com/7K-Inari/inari-server/commit/dab8adeae1abdd58ecf30951bbb69092a467e9e7))


### Bug Fixes

* **agentgateway,cmd:** apply incremental capability updates with advancing checksums; replace deprecated h2c with http.Protocols ([c577ff0](https://github.com/7K-Inari/inari-server/commit/c577ff032ae41d82eae6c838df80c75bf384355d))
* **approvals,orchestrator:** scope approval decisions to caller's org; guard decide race; enforce catalog visibility on deploy ([3ee5ae4](https://github.com/7K-Inari/inari-server/commit/3ee5ae4931fd31eb394ee18f9999c4b1560a2fd4))
* **ci:** detect release merge via manifest change only ([31728f7](https://github.com/7K-Inari/inari-server/commit/31728f72cae6a0f32532e67f962becc849b781a5))
* **ci:** errcheck on response bodies; self-approval check normalizes actor prefix; correct upgrade-flow schema assertion ([60ec559](https://github.com/7K-Inari/inari-server/commit/60ec5597a85b569f7591e489c8721eca3df087db))
* **ci:** goose statement markers for plpgsql function, latest golangci-lint for Go 1.26 ([641ce67](https://github.com/7K-Inari/inari-server/commit/641ce67db4f0e6150c049078e4742e8a33249bc2))
* **httpserver:** init nil SecuritySchemes map and enforce Bearer scheme ([690667f](https://github.com/7K-Inari/inari-server/commit/690667f511b766a6f431d3ebe34dbae63ab6d6a7))
* **orchestrator,catalog,inventory:** typed duplicate-instance and cluster errors, visibility replace semantics, batched badge/list queries, PR head name panic fix + github provider tests ([2e7445e](https://github.com/7K-Inari/inari-server/commit/2e7445e3155a03959b42778da8f729f7557affd2))
