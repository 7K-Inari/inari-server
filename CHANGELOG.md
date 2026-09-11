# Changelog

## [1.8.0](https://github.com/7K-Inari/inari-server/compare/v1.7.0...v1.8.0) (2026-09-11)


### Features

* bootstrap per-tenant platform resources (M7.W2) ([#51](https://github.com/7K-Inari/inari-server/issues/51)) ([91b5ca1](https://github.com/7K-Inari/inari-server/commit/91b5ca1a056a1652045eb52f2b7f437bba15fb55))
* platform resources server skeleton (M7) ([#49](https://github.com/7K-Inari/inari-server/issues/49)) ([c744b87](https://github.com/7K-Inari/inari-server/commit/c744b87b317839c5110f850b49092dcd14c11534))
* **platformresources:** ops reconcile endpoint + tzf platform-manifest teardown (M7.W4) ([#54](https://github.com/7K-Inari/inari-server/issues/54)) ([3fe3011](https://github.com/7K-Inari/inari-server/commit/3fe3011e59b4eca27af68868424e1feb190d0fde))
* **platformresources:** route agent platform CRD status updates to platform_resources (M7.W3) ([#53](https://github.com/7K-Inari/inari-server/issues/53)) ([f466ffc](https://github.com/7K-Inari/inari-server/commit/f466ffc7a439ed46ba5e5fe631f62d5d9df90b9f))
* **scaffold:** M8 software templates — engine, OCI sources, approval gates, and hardening ([#56](https://github.com/7K-Inari/inari-server/issues/56)) ([f46856b](https://github.com/7K-Inari/inari-server/commit/f46856b6ccb8201e6009f49923b08cdbcb54b966))
* **scaffold:** M8 wave 1 foundation — scaffold run schema, types, and config knobs ([#55](https://github.com/7K-Inari/inari-server/issues/55)) ([1fa6f21](https://github.com/7K-Inari/inari-server/commit/1fa6f21196e53262723da2217cf1de08ed51ab27))
* seed reserved platform pseudo-org for platform cluster registration ([#52](https://github.com/7K-Inari/inari-server/issues/52)) ([db767ec](https://github.com/7K-Inari/inari-server/commit/db767ec460935941e4fcb3c1f8451880d72ec7b0))

## [1.7.0](https://github.com/7K-Inari/inari-server/compare/v1.6.0...v1.7.0) (2026-09-11)


### Features

* **approvals:** add per-org approval policy config routes ([#44](https://github.com/7K-Inari/inari-server/issues/44)) ([858b0d8](https://github.com/7K-Inari/inari-server/commit/858b0d8dc32ac890f2c1832d831cdf0db2fe4c3f))
* **authz:** reconcile org team groups for IdP-brokered members ([#48](https://github.com/7K-Inari/inari-server/issues/48)) ([278fcaf](https://github.com/7K-Inari/inari-server/commit/278fcafe640e620f5b2126f4a66684b2909af138))
* **catalog:** tenant-scoped catalog visibility overlay routes ([#42](https://github.com/7K-Inari/inari-server/issues/42)) ([872bfb8](https://github.com/7K-Inari/inari-server/commit/872bfb80580e955e9fa1d96ecdb226ae3d96fbc5))
* **secretstores:** add ESO SecretStore registry ([#46](https://github.com/7K-Inari/inari-server/issues/46)) ([9e0c0f4](https://github.com/7K-Inari/inari-server/commit/9e0c0f436f91c7f96551c0fd5f5bb83a700ce66f))
* **tenancy:** add OIDC client/scope management and declarative RBAC mappings ([#45](https://github.com/7K-Inari/inari-server/issues/45)) ([1127b6b](https://github.com/7K-Inari/inari-server/commit/1127b6b944257ba2b0e8d7c2afdac7ff5db1bacd))
* **tenancy:** add OIDC IdP brokering for tenant organizations ([#47](https://github.com/7K-Inari/inari-server/issues/47)) ([baccd43](https://github.com/7K-Inari/inari-server/commit/baccd43766484b65a89d4a329c2cba6fbbda1f82))
* **tenancy:** tenant-scoped org profile, teams, members, and token management routes ([#43](https://github.com/7K-Inari/inari-server/issues/43)) ([5f3b45d](https://github.com/7K-Inari/inari-server/commit/5f3b45d00f1801c336181375082866266852fbee))


### Bug Fixes

* **ci:** make release.yml the sole release-please detector on push to main ([#40](https://github.com/7K-Inari/inari-server/issues/40)) ([137af3f](https://github.com/7K-Inari/inari-server/commit/137af3f7ebe3cf27ff2d33348d7d634bafe049b0))

## [1.6.0](https://github.com/7K-Inari/inari-server/compare/v1.5.0...v1.6.0) (2026-09-10)


### Features

* add caller-scoped GET /api/v1/approvals/inbox ([#39](https://github.com/7K-Inari/inari-server/issues/39)) ([45c3b7c](https://github.com/7K-Inari/inari-server/commit/45c3b7cdf9074b1b678e2c372e2c5e7d970b5e73))
* **agentgateway:** deliver per-cluster OIDC client secret via Vault + ESO ([#35](https://github.com/7K-Inari/inari-server/issues/35)) ([bc80ac2](https://github.com/7K-Inari/inari-server/commit/bc80ac28504e3b3bf503f833a0f4504a2f9f0322))
* **clusterregistry:** add DELETE cluster endpoint to cancel pending registrations ([#37](https://github.com/7K-Inari/inari-server/issues/37)) ([d5c7a79](https://github.com/7K-Inari/inari-server/commit/d5c7a79702b4eb6a1deebb3687be180c318574e7))


### Bug Fixes

* **catalog:** sync real package versions for platform apps from OCI registry ([#36](https://github.com/7K-Inari/inari-server/issues/36)) ([3a49832](https://github.com/7K-Inari/inari-server/commit/3a49832a75549b301bf4d3e9a4e6be2780f18cea))

## [1.5.0](https://github.com/7K-Inari/inari-server/compare/v1.4.1...v1.5.0) (2026-09-07)


### Features

* **charts:** dedicated agent-gateway hostname via route.agentHostnames ([#33](https://github.com/7K-Inari/inari-server/issues/33)) ([ffc9d13](https://github.com/7K-Inari/inari-server/commit/ffc9d134b5f82aa77a2f29dd8977cf8bbd045040))

## [1.4.1](https://github.com/7K-Inari/inari-server/compare/v1.4.0...v1.4.1) (2026-09-07)


### Bug Fixes

* agent install manifest drift + route ConnectRPC paths on the gateway chart ([#30](https://github.com/7K-Inari/inari-server/issues/30)) ([7cc505a](https://github.com/7K-Inari/inari-server/commit/7cc505a24d07c8887fd5c8e87d34b2d9b078ac37))

## [1.4.0](https://github.com/7K-Inari/inari-server/compare/v1.3.1...v1.4.0) (2026-09-03)


### Features

* **authz:** add platform-global type to OpenFGA model ([#25](https://github.com/7K-Inari/inari-server/issues/25)) ([830ab8b](https://github.com/7K-Inari/inari-server/commit/830ab8bfcdeb97a48c83d99fdd21781e37bd87f9))
* **authz:** platform permission surface, org_creator enforcement and group sync (M1.W2) ([#27](https://github.com/7K-Inari/inari-server/issues/27)) ([48c6c2a](https://github.com/7K-Inari/inari-server/commit/48c6c2a94eabf166f1709a9c74b0340d0dbce97f))

## [1.3.1](https://github.com/7K-Inari/inari-server/compare/v1.3.0...v1.3.1) (2026-08-30)


### Bug Fixes

* **ci:** publish chart to repo-scoped GHCR path and make package public ([#23](https://github.com/7K-Inari/inari-server/issues/23)) ([92ad228](https://github.com/7K-Inari/inari-server/commit/92ad2281f5062c00dca3ad9ff702c3465e7060e7))

## [1.3.0](https://github.com/7K-Inari/inari-server/compare/v1.2.0...v1.3.0) (2026-08-28)


### Features

* add inari-server helm chart ([#20](https://github.com/7K-Inari/inari-server/issues/20)) ([721d593](https://github.com/7K-Inari/inari-server/commit/721d59340945a6a0f068f78fc4e61be4f3352cbf))

## [1.2.0](https://github.com/7K-Inari/inari-server/compare/v1.1.0...v1.2.0) (2026-08-27)


### Features

* authenticate to Keycloak Admin REST via service account ([#18](https://github.com/7K-Inari/inari-server/issues/18)) ([b88f627](https://github.com/7K-Inari/inari-server/commit/b88f6276ab04b1ae57a478e9ee70e1172577d9e3))

## [1.1.0](https://github.com/7K-Inari/inari-server/compare/v1.0.0...v1.1.0) (2026-08-21)


### Features

* **ci:** golden-path e2e gate on kind ([3bc64ea](https://github.com/7K-Inari/inari-server/commit/3bc64ea91572e6a8272a42f3614a4ea016e0f9e9))
* cluster lifecycle states + Tenant Zone Factory (M3-W2) ([#10](https://github.com/7K-Inari/inari-server/issues/10)) ([dea4c00](https://github.com/7K-Inari/inari-server/commit/dea4c00d77b573fe25001450614e13e892b72032))
* **m3:** cloud accounts, approvals, notifications, policy service, impersonation ([#9](https://github.com/7K-Inari/inari-server/issues/9)) ([a6e0093](https://github.com/7K-Inari/inari-server/commit/a6e0093d8e537a37f0d65423c9cd1ff4c665a691))
* **m4:** extension host + fleet manager (WAVE 2) ([#12](https://github.com/7K-Inari/inari-server/issues/12)) ([81d36ea](https://github.com/7K-Inari/inari-server/commit/81d36ea54e974c837f51ff2ebbc05330373ae6e9))
* offline OpenAPI export of the full REST surface ([#11](https://github.com/7K-Inari/inari-server/issues/11)) ([10e644e](https://github.com/7K-Inari/inari-server/commit/10e644ef72214aee8925f80c112871aa11f3b8b7))
* **tenancy:** creator auto-membership and team membership API ([5e32fed](https://github.com/7K-Inari/inari-server/commit/5e32fedf36da86f9b8cfa9e336be0f7531a7d4b2))
* **tenancy:** creator auto-membership and team membership API ([5727368](https://github.com/7K-Inari/inari-server/commit/5727368f9d3cad23067c98aea2ca28aa7ef7b9b6))


### Bug Fixes

* agent client audience mapper + install-manifest alignment (M2.1) ([5968481](https://github.com/7K-Inari/inari-server/commit/5968481d7b94efd1012d5ea633aee7fb8809da44))
* **ci:** fetch helm chart dependencies before the golden-path e2e run ([522c3ce](https://github.com/7K-Inari/inari-server/commit/522c3ce46a6ffff26785bc279f07ae8848f400fa))
* **ci:** resolve agent Dockerfile path in e2e build; correct stale tuple-object assertion in tenancy integration test ([a22cbbf](https://github.com/7K-Inari/inari-server/commit/a22cbbf51ede3ec014c6206dfae0dca2b96564d3))
* **clusterregistry:** align rendered agent manifest with agent env contract and RBAC ([b544c9e](https://github.com/7K-Inari/inari-server/commit/b544c9e6673fed365b7856b7eefbaebd47bb68ea))
* **clusterregistry:** update NewHandler call in integration test for capabilities dependency ([f122b8c](https://github.com/7K-Inari/inari-server/commit/f122b8ce7ae2e7b58ee182db4c852db4623f50b4))
* golden-path runtime blockers + kind e2e gate ([179340c](https://github.com/7K-Inari/inari-server/commit/179340c80b41a4f49303f9861d723191759eda2b))
* **tenancy:** add inari-server audience mapper to cluster OIDC clients ([52b2533](https://github.com/7K-Inari/inari-server/commit/52b253310a6eaef77762da40c95ce1eba497474a))
* **tenancy:** make membership add/remove idempotent ([dca05bc](https://github.com/7K-Inari/inari-server/commit/dca05bc78304c9ae67177b3aab9a580bc76424e0))
* **tenancy:** serialize concurrent membership add/remove on the unique PK ([7eed6a7](https://github.com/7K-Inari/inari-server/commit/7eed6a7258fe5a215283fa1768954731d4e49614))
* unblock the golden path end-to-end ([8b0ea7d](https://github.com/7K-Inari/inari-server/commit/8b0ea7d2b06ce8db3a1a1627254bb8d92880f464))

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
