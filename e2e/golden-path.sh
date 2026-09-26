#!/usr/bin/env bash
# e2e golden path (CI gate): platform stack on kind → tenant → cluster
# registration → agent connect → capabilities streaming.
#
# Mirrors the manually validated flow. All HTTP calls run through a toolbox
# pod in the cluster (kubectl exec) so the script is immune to
# port-forward fragility. It intentionally performs a few Keycloak
# provisioning steps imperatively (audience mapper)
# that are not yet automated in inari-server — each is marked GAP(n) and maps
# to a tracked upstream fix; the script must keep
# passing once those land. The OIDC client-secret delivery is fully
# automated: Vault (dev mode) + ESO + the manifest-rendered ExternalSecret.
#
# Prereqs: docker, kind, kubectl, helm, jq. Configurable via env:
#   CLUSTER_NAME (default inari-e2e)
#   SERVER_IMAGE / AGENT_IMAGE (default inari/server:e2e / inari/agent:e2e)
#   HELM_CHARTS_DIR (default ../inari-helm-charts — checkout of the
#     inari-helm-charts repo providing charts/platform-config + scripts)
#   SERVER_CHART_DIR (default ./charts/inari-server)
#   AGENT_CHART_DIR (default ../inari-agent/charts/inari-agent — the
#     inari-agent repo checkout the e2e workflow nests in the repo root)
#   KEEP_CLUSTER=true to skip teardown
#   INARI_E2E_CACHE_BACKEND=memory|redis (default memory; default redis when
#     INARI_HA=true) — redis installs the chart's bitnami/redis subchart and
#     points the cache layer at it
#   INARI_HA=true (default false) — HA mode (Wave 2, 99.9% initiative):
#     inari-server replicaCount=2 via the W1 chart knobs (probes, PDB,
#     anti-affinity, rollingUpdate maxUnavailable: 0), OpenFGA
#     replicaCount=2, plus clearly delimited HA-only disruption assertions
#     after the golden path passes (pod kill, rollout restart under
#     traffic, migration-lock race, leader-lease single-execution, agent
#     stream fencing). The non-HA path is byte-identical in behavior and
#     timing and stays the fast default gate. NATS is 3-node JetStream in
#     BOTH modes (W1 provisioned it HA from day one). The inari console +
#     operator charts are not part of this stack (server + agent only);
#     their W1 HA guardrails live in their own repos.
#     Backend constraints in HA mode:
#     - INARI_GIT_PROVIDER=local stays: the bare-repo root is a hostPath
#       shared by every replica through the kind node mount.
#     - TZF fake AWS backends keep state per-pod (in-memory): the golden
#       path makes no TZF-zone assertions, and any future one must be
#       skipped or pinned to a single pod under INARI_HA.
#     - No assertion needs the github provider; if one is added, gate it
#       on INARI_GITHUB_APP_ID + INARI_GITHUB_APP_PRIVATE_KEY_FILE.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-inari-e2e}"
SERVER_IMAGE="${SERVER_IMAGE:-inari/server:e2e}"
AGENT_IMAGE="${AGENT_IMAGE:-inari/agent:e2e}"
HELM_CHARTS_DIR="${HELM_CHARTS_DIR:-$(dirname "$0")/../../inari-helm-charts}"
PLATFORM_CHART_DIR="${PLATFORM_CHART_DIR:-$HELM_CHARTS_DIR/charts/platform-config}"
SERVER_CHART_DIR="${SERVER_CHART_DIR:-$(dirname "$0")/../charts/inari-server}"
AGENT_CHART_DIR="${AGENT_CHART_DIR:-$(dirname "$0")/../inari-agent/charts/inari-agent}"
NAMESPACE="${NAMESPACE:-inari}"
TENANT="${TENANT:-e2e-org}"
KEEP_CLUSTER="${KEEP_CLUSTER:-false}"
TOOLS=golden-path-tools
KC_FQDN="keycloak-service.${NAMESPACE}.svc:8080"
SERVER_SVC="inari-server"
VAULT_DEV_TOKEN="${VAULT_DEV_TOKEN:-e2e-root-token}"
# HA mode (default off). Only replica counts and HA-only assertion blocks
# branch on this — every other step is identical between modes.
INARI_HA="${INARI_HA:-false}"
[ "$INARI_HA" = "true" ] || [ "$INARI_HA" = "false" ] || \
  die "INARI_HA must be true or false (got: $INARI_HA)"
SERVER_REPLICAS=1
OPENFGA_REPLICAS=1
if $INARI_HA; then
  SERVER_REPLICAS=2
  OPENFGA_REPLICAS=2
fi
# Cache backend: memory is per-pod (the PEP generation bump is
# process-local, so cross-replica invalidation degrades to the 2s PEP
# TTL); HA defaults to the shared redis backend per the chart's
# multi-replica guidance. Non-HA default stays memory (unchanged).
CACHE_BACKEND="${INARI_E2E_CACHE_BACKEND:-}"
if [ -z "$CACHE_BACKEND" ]; then
  if $INARI_HA; then CACHE_BACKEND=redis; else CACHE_BACKEND=memory; fi
fi
[ "$CACHE_BACKEND" = "memory" ] || [ "$CACHE_BACKEND" = "redis" ] || \
  die "INARI_E2E_CACHE_BACKEND must be memory or redis (got: $CACHE_BACKEND)"

log() { printf '\033[1;34m[e2e]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[e2e] %s\033[0m\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "missing prerequisite: $1"; }
need docker; need kubectl; need helm; need jq; need kind; need git; need base64

# Host-side git root for INARI_GIT_PROVIDER=local: the server writes real
# bare repos here (mounted into the kind node), and this script clones and
# applies baseline/rbac/ from them — GAP(rbac-e2e-argocd): this stands in
# for the tenant-local ArgoCD, which the e2e platform stack does not
# install ("platform stack without ArgoCD", see below).
GIT_HOST_DIR="$(mktemp -d /tmp/inari-e2e-git.XXXXXX)"
# mktemp dirs are 0700; the server container runs non-root, so open the
# shared git root up (it is bind-mounted into the kind node at /git and
# hostPath-mounted into the server pod at /var/lib/inari/git).
chmod 0777 "$GIT_HOST_DIR"

cleanup() {
  kubectl -n "$NAMESPACE" delete pod "$TOOLS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  $KEEP_CLUSTER || kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
  $KEEP_CLUSTER || rm -rf "$GIT_HOST_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# xcurl runs curl inside the toolbox pod (never on the host).
xcurl() { kubectl -n "$NAMESPACE" exec "$TOOLS" -- curl -sf -m 20 "$@"; }

log "creating kind cluster '$CLUSTER_NAME'"
kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
# extraMounts: the host git root lands at /git inside the kind node so the
# server pod can hostPath-mount it for the local git provider.
kind create cluster --name "$CLUSTER_NAME" --wait 60s \
  --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: $GIT_HOST_DIR
        containerPath: /git
EOF
kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null

log "loading images ($SERVER_IMAGE, $AGENT_IMAGE)"
kind load docker-image "$SERVER_IMAGE" "$AGENT_IMAGE" --name "$CLUSTER_NAME"

log "installing prerequisite operators (CNPG + Keycloak — the charts never install operators)"
"$HELM_CHARTS_DIR/scripts/install-operators.sh"

# Platform stack without ArgoCD: the gitops-composed pieces installed by hand
# (platform-config from git, NATS/OpenFGA from their public helm repos, values
# mirroring gitops/platform/*.yaml), then the inari-server chart from this
# repo with the e2e images.
log "installing platform-config (CNPG cluster + db secrets + Keycloak realm)"
helm upgrade --install platform-config "$PLATFORM_CHART_DIR" \
  --namespace "$NAMESPACE" --create-namespace \
  --set postgresql.storageSize=1Gi \
  --set keycloak.hostname.hostname=http://keycloak.local:8080 \
  --set keycloak.resources.requests.cpu=100m \
  --set keycloak.resources.requests.memory=256Mi \
  --wait --timeout 10m

# helm --wait does not cover CR-only resources (CNPG Cluster, Keycloak CR);
# wait until the operators have the database and Keycloak actually running,
# otherwise the inari-server pods below can never become ready.
log "waiting for PostgreSQL (CNPG) and Keycloak"
kubectl -n "$NAMESPACE" wait --for=condition=Ready cluster.postgresql.cnpg.io/postgresql --timeout=600s
kubectl -n "$NAMESPACE" rollout status statefulset/keycloak --timeout=420s

log "pinning Keycloak hostname to the in-cluster FQDN (issuer consistency)"
# With a dynamic hostname, token issuers vary by request host and never match
# the server's configured issuer. The FQDN resolves from every namespace
# (server in $NAMESPACE, agent in inari-system). In production this is a real
# DNS name reachable from both sides. This must happen BEFORE inari-server is
# installed: the server derives its expected issuer from keycloak.baseUrl and
# crashes on OIDC discovery if the provider still reports keycloak.local.
kubectl -n "$NAMESPACE" wait --for=condition=complete job -l app.kubernetes.io/component=keycloak --timeout=300s 2>/dev/null || true
kubectl -n "$NAMESPACE" patch keycloak keycloak --type merge \
  -p "{\"spec\":{\"hostname\":{\"hostname\":\"http://$KC_FQDN\",\"strict\":true}}}"
kubectl -n "$NAMESPACE" rollout status statefulset/keycloak --timeout=420s

log "installing NATS (JetStream, 3-node cluster)"
# NATS is the reserved M1 event-bus seam (the outbox dispatcher is still
# in-process; no server client exists yet) and is provisioned HA from day
# one — part of the 99.9% availability initiative, so M1 lands on an
# already-clustered substrate. e2e/nats-values.yaml mirrors the production
# posture:
#   - 3-node cluster (JetStream meta group quorum), one fileStore PVC per pod
#   - R=3 streams (replicas=3) so any single node loss keeps the stream live
#   - advised limits: size fileStore per retention budget and set explicit
#     max_memory_store/max_file_store; keep per-stream consumer counts
#     bounded (prefer few durable consumers over many ephemeral ones)
# The full operations docs page is a separate task.
helm repo add openfga https://openfga.github.io/helm-charts >/dev/null
helm repo add nats https://nats-io.github.io/k8s/helm/charts/ >/dev/null
helm repo update >/dev/null
helm upgrade --install nats nats/nats --version 1.3.2 \
  --namespace "$NAMESPACE" \
  -f "$(dirname "$0")/nats-values.yaml" \
  --wait --timeout 8m

# Belt-and-braces on top of helm --wait (the StatefulSet readiness probe
# /healthz?js-server-only=true already gates on meta-group currency): assert
# the JetStream meta group actually formed with 3 members and a leader.
# The monitor port 8222 lives only on the nats-headless service (the nats
# ClusterIP service exposes just 4222), so jsz must be scraped there.
log "verifying the JetStream meta group (3 members + leader)"
for i in $(seq 1 24); do
  JSZ=$(kubectl -n "$NAMESPACE" exec deploy/nats-box -- \
    sh -c 'curl -sf http://nats-headless:8222/jsz' 2>/dev/null || true)
  if jq -e '.meta_cluster.cluster_size == 3 and (.meta_cluster.leader | type == "string" and length > 0)' \
      <<<"$JSZ" >/dev/null 2>&1; then
    break
  fi
  sleep 5
  [ "$i" = 24 ] && die "JetStream meta group never formed (jsz: ${JSZ:-empty}; logs: kubectl -n $NAMESPACE logs statefulset/nats)"
done

log "installing OpenFGA (postgres datastore via the inari-db secret)"
# Always installed single-replica first: OpenFGA runs its datastore
# migrations in a per-pod initContainer with no cross-pod locking, so a
# fresh 2-replica install would race goose migrations on an empty
# database. HA mode scales out AFTER the first pod has applied them.
helm upgrade --install openfga openfga/openfga --version 0.2.27 \
  --namespace "$NAMESPACE" \
  --set fullnameOverride=openfga \
  --set replicaCount=1 \
  --set datastore.engine=postgres \
  --set datastore.existingSecret=inari-db \
  --set datastore.secretKeys.uriKey=openfga-uri \
  --set datastore.migrationType=initContainer \
  --set playground.enabled=false \
  --wait --timeout 5m
if [ "$OPENFGA_REPLICAS" -gt 1 ]; then
  log "HA: scaling OpenFGA to $OPENFGA_REPLICAS replicas (migrations already applied)"
  kubectl -n "$NAMESPACE" scale deployment/openfga --replicas="$OPENFGA_REPLICAS"
  kubectl -n "$NAMESPACE" rollout status deployment/openfga --timeout=240s
fi

log "installing Vault (dev mode) + ESO for the OIDC client-secret delivery path"
helm repo add hashicorp https://helm.releases.hashicorp.com >/dev/null
helm repo add external-secrets https://charts.external-secrets.io >/dev/null
helm repo update >/dev/null
helm upgrade --install vault hashicorp/vault \
  --namespace "$NAMESPACE" \
  --set server.dev.enabled=true \
  --set server.dev.devRootToken="$VAULT_DEV_TOKEN" \
  --set injector.enabled=false \
  --wait --timeout 5m
helm upgrade --install external-secrets external-secrets/external-secrets \
  --namespace external-secrets --create-namespace \
  --set installCRDs=true \
  --wait --timeout 5m
# helm --wait covers the controller deployments, not CRD establishment;
# applying a ClusterSecretStore before the API is established fails with
# "no matches for kind".
kubectl wait --for=condition=established crd/clustersecretstores.external-secrets.io --timeout=120s
kubectl wait --for=condition=established crd/externalsecrets.external-secrets.io --timeout=120s
kubectl -n "$NAMESPACE" create secret generic inari-vault \
  --from-literal=token="$VAULT_DEV_TOKEN" --dry-run=client -o yaml | kubectl apply -f -

log "installing inari-server chart (e2e image, cache backend: $CACHE_BACKEND)"
# The optional redis subchart must be vendored even when disabled: helm
# verifies all Chart.yaml dependencies are present in charts/ on install.
helm repo add bitnami https://charts.bitnami.com/bitnami >/dev/null
helm dependency build "$SERVER_CHART_DIR" >/dev/null
CACHE_HELM_ARGS=()
if [ "$CACHE_BACKEND" = "redis" ]; then
  CACHE_HELM_ARGS+=(--set redis.enabled=true --set cache.backend=redis)
fi
EXTRA_ENV="[
    {\"name\":\"INARI_AGENT_GATEWAY_ADDRESS\",\"value\":\"http://$SERVER_SVC.${NAMESPACE}.svc:8080\"},
    {\"name\":\"INARI_AGENT_IMAGE_REPO\",\"value\":\"inari/agent\"},
    {\"name\":\"INARI_GIT_PROVIDER\",\"value\":\"local\"},
    {\"name\":\"INARI_GIT_LOCAL_ROOT\",\"value\":\"/var/lib/inari/git\"}"
if $INARI_HA; then
  # HA-only scaffold knobs: disruption block HA(a) drives a real scaffold
  # run to prove the claim-based reconcile loop keeps progressing work
  # after a pod loss. The templates are baked into the image at
  # /templates; the local git provider receives repos under
  # $INARI_GIT_LOCAL_ROOT/e2e-platform/. Never set in non-HA mode.
  EXTRA_ENV="$EXTRA_ENV,
    {\"name\":\"INARI_SCAFFOLD_TEMPLATE_DIR\",\"value\":\"/templates\"},
    {\"name\":\"INARI_SCAFFOLD_GIT_ORG\",\"value\":\"e2e-platform\"},
    {\"name\":\"INARI_SCAFFOLD_RECONCILE_INTERVAL\",\"value\":\"5s\"}"
fi
EXTRA_ENV="$EXTRA_ENV
  ]"
helm upgrade --install inari-server "$SERVER_CHART_DIR" \
  --namespace "$NAMESPACE" \
  --set replicaCount="$SERVER_REPLICAS" \
  --set image.repository="${SERVER_IMAGE%:*}" \
  --set image.tag="${SERVER_IMAGE##*:}" \
  --set image.pullPolicy=IfNotPresent \
  --set keycloak.baseUrl="http://$KC_FQDN" \
  --set vault.addr="http://vault.${NAMESPACE}.svc:8200" \
  ${CACHE_HELM_ARGS[@]+"${CACHE_HELM_ARGS[@]}"} \
  --set-json "extraEnv=$EXTRA_ENV" \
  --set-json "extraVolumes=[
    {\"name\":\"git-repos\",\"hostPath\":{\"path\":\"/git\",\"type\":\"Directory\"}}
  ]" \
  --set-json "extraVolumeMounts=[
    {\"name\":\"git-repos\",\"mountPath\":\"/var/lib/inari/git\"}
  ]" \
  --wait --timeout 10m
kubectl -n "$NAMESPACE" rollout status deployment/inari-server --timeout=180s

# ==================== HA-only (c): fresh 0→2 scale-up ====================
# The install above IS the fresh 0→2 scale-up on a clean namespace: both
# replicas boot simultaneously against an empty database and the W1
# migration advisory lock (ADR-0010) serializes their goose runs. The
# asserted outcome is the one the lock exists to guarantee: with
# concurrent first boots, every migration is applied exactly once and
# both replicas become Ready. Boot-LOG evidence is deliberately NOT
# asserted: goose only engages (and logs) the locker while migrations
# are pending, and pods that restart during stack bring-up (Keycloak
# warmup 500s rotate logs away) leave no trace — the lock mechanics
# themselves are covered deterministically by W1's internal/db
# integration tests. The acquisition-line count is printed as soft CI
# evidence only.
if $INARI_HA; then
  log "HA(c): fresh 0->2 scale-up — migrations serialized by the advisory lock, both replicas ready"
  kubectl -n "$NAMESPACE" wait --for=condition=ready pod \
    -l app.kubernetes.io/name=inari-server --timeout=300s
  # psql_inari runs SQL against the platform database via the CNPG
  # primary pod (the toolbox image has curl only; the connection URI
  # never leaves the cluster). Also used by the HA(d1) block below.
  psql_inari() {
    local uri primary
    uri=$(kubectl -n "$NAMESPACE" get secret inari-db -o jsonpath='{.data.inari-uri}' | base64 -d)
    primary=$(kubectl -n "$NAMESPACE" get cluster.postgresql.cnpg.io/postgresql -o jsonpath='{.status.currentPrimary}')
    kubectl -n "$NAMESPACE" exec "$primary" -c postgres -- psql "$uri" -tAc "$1"
  }
  EXPECTED_MIGRATIONS=$(find "$(dirname "$0")/../internal/db/migrations" -name '[0-9]*.sql' | wc -l)
  APPLIED_MIGRATIONS=$(psql_inari "SELECT max(version_id) FROM goose_db_version")
  [ "$APPLIED_MIGRATIONS" = "$EXPECTED_MIGRATIONS" ] \
    || die "HA(c): goose_db_version is at $APPLIED_MIGRATIONS, want $EXPECTED_MIGRATIONS (concurrent first-boot migrations did not converge)"
  LOCK_LINES=$(kubectl -n "$NAMESPACE" logs -l app.kubernetes.io/name=inari-server --tail=-1 2>/dev/null | grep -c 'db: migration lock acquired' || true)
  log "HA(c): migrations converged at version $APPLIED_MIGRATIONS; advisory-lock acquisitions visible in current logs: ${LOCK_LINES:-0} (informational)"
  # The W1 chart knobs at replicaCount >= 2: PDB (minAvailable: 1) and
  # rollingUpdate maxUnavailable: 0.
  kubectl -n "$NAMESPACE" get pdb inari-server >/dev/null \
    || die "HA(c): PodDisruptionBudget inari-server missing at replicaCount=2"
  [ "$(kubectl -n "$NAMESPACE" get pdb inari-server -o jsonpath='{.spec.minAvailable}')" = "1" ] \
    || die "HA(c): pdb minAvailable != 1"
  kubectl -n "$NAMESPACE" get deployment inari-server -o jsonpath='{.spec.strategy.rollingUpdate.maxUnavailable}' \
    | grep -q '^0' || die "HA(c): rollingUpdate.maxUnavailable is not 0"
fi

log "starting toolbox pod"
kubectl -n "$NAMESPACE" delete pod "$TOOLS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
kubectl -n "$NAMESPACE" run "$TOOLS" --image=curlimages/curl:8.10.1 --restart=Never \
  --overrides='{"spec":{"securityContext":{"runAsUser":1000}}}' --command -- sleep 3600 >/dev/null
kubectl -n "$NAMESPACE" wait --for=condition=ready "pod/$TOOLS" --timeout=120s >/dev/null

log "waiting for the Keycloak issuer to converge on the FQDN"
for i in $(seq 1 24); do
  ISS=$(xcurl "http://keycloak-service:8080/realms/inari/.well-known/openid-configuration" | jq -r .issuer 2>/dev/null || true)
  [ "$ISS" = "http://$KC_FQDN/realms/inari" ] && break
  sleep 5
  [ "$i" = 24 ] && die "issuer did not converge to $KC_FQDN (got: $ISS)"
done

admin_token() {
  local secret
  secret=$(kubectl -n "$NAMESPACE" get secret inari-keycloak-admin -o jsonpath='{.data.client-secret}' | base64 -d)
  xcurl "http://keycloak-service:8080/realms/inari/protocol/openid-connect/token" \
    -d grant_type=client_credentials -d client_id=inari-platform-admin -d client_secret="$secret" \
    | jq -r .access_token
}
user_token() {
  xcurl "http://keycloak-service:8080/realms/inari/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=inari-server \
    -d username=dev-admin -d password=dev-admin -d scope="openid organization:*" \
    | jq -r .access_token
}

AT="$(admin_token)"

log "GAP(kc-realm): ensuring dev user + public client with correct scopes"
KC_UID=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/users?username=dev-admin" | jq -r '.[0].id // empty')
if [ -z "$KC_UID" ]; then
  xcurl -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
    -d '{"username":"dev-admin","enabled":true,"email":"dev-admin@inari.local","emailVerified":true,"firstName":"Dev","lastName":"Admin","credentials":[{"type":"password","value":"dev-admin","temporary":false}]}' \
    -o /dev/null "http://keycloak-service:8080/admin/realms/inari/users"
  KC_UID=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/users?username=dev-admin" | jq -r '.[0].id')
fi
# KC 26.x: create alone can leave the account unverified — force the final state.
xcurl -X PUT -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
  -d '{"emailVerified":true,"firstName":"Dev","lastName":"Admin","requiredActions":[],"enabled":true}' \
  -o /dev/null "http://keycloak-service:8080/admin/realms/inari/users/$KC_UID"
KC_CLIENT=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/clients?clientId=inari-server" | jq -r '.[0].id // empty')
if [ -z "$KC_CLIENT" ]; then
  xcurl -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
    -d '{"clientId":"inari-server","enabled":true,"publicClient":true,"standardFlowEnabled":true,"directAccessGrantsEnabled":true,"redirectUris":["http://localhost/*"],"webOrigins":["+"],"defaultClientScopes":["openid","profile","email","organization"]}' \
    -o /dev/null "http://keycloak-service:8080/admin/realms/inari/clients"
  KC_CLIENT=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/clients?clientId=inari-server" | jq -r '.[0].id')
fi
# GAP(aud-mapper): server validates aud=inari-server.
for i in 1 2 3; do
  MAPPERS=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/clients/$KC_CLIENT/protocol-mappers/models" | jq -r '.[].name' || true)
  grep -q audience-inari-server <<<"$MAPPERS" && break
  xcurl -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
    -d '{"name":"audience-inari-server","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.client.audience":"inari-server","id.token.claim":"false","access.token.claim":"true","userinfo.token.claim":"false"}}' \
    -o /dev/null "http://keycloak-service:8080/admin/realms/inari/clients/$KC_CLIENT/protocol-mappers/models" || true
  sleep 2
done
# GAP(basic-scope): without the basic scope, tokens carry no sub claim.
BASIC_ID=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/client-scopes" | jq -r '.[] | select(.name=="basic") | .id')
kubectl -n "$NAMESPACE" exec "$TOOLS" -- curl -s -o /dev/null -X PUT -H "Authorization: Bearer $AT" \
  "http://keycloak-service:8080/admin/realms/inari/clients/$KC_CLIENT/default-client-scopes/$BASIC_ID"
# Sanity: a token must carry sub and aud=inari-server before we proceed.
PROBE="$(user_token)"
PAYLOAD=$(cut -d. -f2 <<<"$PROBE"); PAYLOAD="${PAYLOAD}$(printf '=%.0s' $(seq 1 $(( (4 - ${#PAYLOAD} % 4) % 4 ))))"
CLAIMS=$(base64 -d <<<"$PAYLOAD" 2>/dev/null || base64 -D <<<"$PAYLOAD")
jq -e '.sub != null' <<<"$CLAIMS" >/dev/null || die "token has no sub claim (basic scope missing)"
jq -e '.aud == "inari-server" or (.aud | type == "array" and index("inari-server"))' <<<"$CLAIMS" >/dev/null \
  || die "token has wrong aud (audience mapper missing): $(jq -c .aud <<<"$CLAIMS")"

API="http://$SERVER_SVC:8080/api/v1"
log "GAP(kc-platform-group): ensuring dev-admin is in platform-admins (drives org_creator tuple sync)"
GROUP_ID=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/groups?exact=true&search=platform-admins" | jq -r '.[0].id // empty')
if [ -z "$GROUP_ID" ]; then
  xcurl -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
    -d '{"name":"platform-admins"}' -o /dev/null -w '%{http_code}' \
    "http://keycloak-service:8080/admin/realms/inari/groups" | grep -qE '201|409' \
    || die "failed to create platform-admins group"
  GROUP_ID=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/groups?exact=true&search=platform-admins" | jq -r '.[0].id')
fi
# Join is idempotent (204); the server's platform group sync reconciler turns
# membership into platform:inari org_creator tuples within its poll interval.
xcurl -o /dev/null -X PUT \
  -H "Authorization: Bearer $AT" \
  "http://keycloak-service:8080/admin/realms/inari/users/$KC_UID/groups/$GROUP_ID" \
  || die "failed to add dev-admin to platform-admins"

log "waiting for the platform group sync to grant dev-admin org_creator"
if $INARI_HA; then
  # HA(c) companion assertion: the replicas' FGA store bootstrap must have
  # converged on exactly ONE store named "inari". A duplicate means the
  # bootstrap lease (authz-fga-bootstrap) failed and each replica pinned
  # its own store — split-brain authz (tuple writes invisible to the other
  # pod's Checks). stores[0] below would silently hide that.
  FGA_STORE_COUNT=$(xcurl "http://openfga:8080/stores" | jq '[.stores[] | select(.name=="inari")] | length')
  [ "$FGA_STORE_COUNT" = "1" ] \
    || die "HA(c): $FGA_STORE_COUNT OpenFGA stores named 'inari' (store bootstrap race — replicas would split-brain)"
fi
FGA_STORE=$(xcurl "http://openfga:8080/stores" | jq -r '.stores[0].id')
ORG_CREATOR=false
for i in $(seq 1 18); do
  ORG_CREATOR=$(xcurl -X POST "http://openfga:8080/stores/$FGA_STORE/check" -H "Content-Type: application/json" \
    -d "{\"tuple_key\":{\"user\":\"user:$KC_UID\",\"relation\":\"org_creator\",\"object\":\"platform:inari\"}}" | jq -r .allowed 2>/dev/null || echo false)
  [ "$ORG_CREATOR" = "true" ] && break
  sleep 5
done
[ "$ORG_CREATOR" = "true" ] || die "org_creator tuple never appeared (platform group sync not running?)"

log "verifying /me/permissions reflects the org_creator tuple"
PERMS=$(xcurl -H "Authorization: Bearer $(user_token)" "$API/me/permissions" 2>/dev/null || true)
jq -e '.canCreateOrganizations == true' <<<"$PERMS" >/dev/null \
  || die "me/permissions = $PERMS, want canCreateOrganizations=true"

log "creating tenant '$TENANT'"
TENANT_RESP=""
for i in $(seq 1 12); do
  TOKEN="$(user_token || true)"
  if [ -n "$TOKEN" ]; then
    TENANT_RESP=$(kubectl -n "$NAMESPACE" exec "$TOOLS" -- curl -s -m 15 -X POST \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d "{\"slug\":\"$TENANT\",\"displayName\":\"E2E Org\"}" "$API/tenants")
    jq -e '.organization.keycloakOrgId' <<<"$TENANT_RESP" >/dev/null 2>&1 && break
  fi
  sleep 10
done
jq -e '.organization.keycloakOrgId' <<<"$TENANT_RESP" >/dev/null \
  || die "tenant creation failed after retries: $TENANT_RESP"
ORG_KC_ID=$(jq -r '.organization.keycloakOrgId' <<<"$TENANT_RESP")

log "verifying creator auto-membership seeded OpenFGA (outbox → tuple writer)"
# CreateTenant adds the creator to the Keycloak org + platform-team group and
# emits membership.added; the outbox dispatcher seeds the team membership and
# team→org role tuples asynchronously — poll instead of racing it.
FGA_STORE=$(xcurl "http://openfga:8080/stores" | jq -r '.stores[0].id')
ALLOWED=false
for i in $(seq 1 18); do
  ALLOWED=$(xcurl -X POST "http://openfga:8080/stores/$FGA_STORE/check" -H "Content-Type: application/json" \
    -d "{\"tuple_key\":{\"user\":\"user:$KC_UID\",\"relation\":\"platform_engineer\",\"object\":\"organization:$ORG_KC_ID\"}}" | jq -r .allowed 2>/dev/null || echo false)
  [ "$ALLOWED" = "true" ] && break
  sleep 5
done
[ "$ALLOWED" = "true" ] || die "OpenFGA check failed (creator auto-membership did not propagate via outbox)"

log "verifying /metrics exposes the cache layer series (backend: $CACHE_BACKEND)"
# Tenant creation above already drove org lookups + FGA checks through the
# caches, so the series exist; the scrape just must surface them.
# HA: /metrics via the Service hits a RANDOM replica, and OTel counters
# only export a series after that pod's first observation — a replica that
# has served no cache traffic since its last restart legitimately shows
# nothing. Scrape every server pod directly and require the series on at
# least one (the assertion's purpose: the cache layer emits metrics).
metrics_bodies() {
  if $INARI_HA; then
    local ip
    for ip in $(kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/name=inari-server \
        -o jsonpath='{.items[*].status.podIP}'); do
      xcurl "http://$ip:8080/metrics" 2>/dev/null || true
    done
  else
    xcurl "http://$SERVER_SVC:8080/metrics"
  fi
}
METRICS_BODY=$(metrics_bodies)
grep -q "inari_cache_operations_total" <<<"$METRICS_BODY" \
  || die "/metrics missing inari_cache_operations_total"
grep -q "inari_fga_check_duration_seconds" <<<"$METRICS_BODY" \
  || die "/metrics missing inari_fga_check_duration_seconds"

log "registering cluster + issuing token"
TOKEN="$(user_token)"
CLUSTER_RESP=$(xcurl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"e2e-self","labels":{"e2e":"true"}}' "$API/tenants/$TENANT/clusters")
CLUSTER_ID=$(jq -r '.cluster.id' <<<"$CLUSTER_RESP")
ORG_ID=$(jq -r '.cluster.orgId' <<<"$CLUSTER_RESP")
TOK_RESP=$(xcurl -X POST -H "Authorization: Bearer $(user_token)" \
  "$API/tenants/$TENANT/clusters/$CLUSTER_ID/tokens")

log "installing agent via the inari-agent Helm chart"
REG_TOKEN=$(jq -r '.token' <<<"$TOK_RESP")
# No --namespace: the chart renders and owns the inari-system Namespace
# itself (same invocation the Register Cluster wizard shows users).
# oidcSecret.remotePath: the control plane writes the OIDC client secret at
# the trimmed Vault path (secrets.ClusterOIDCPath strips the "cluster:"
# type prefix from the cluster ID).
helm upgrade --install inari-agent "$AGENT_CHART_DIR" \
  --set image.repository="${AGENT_IMAGE%:*}" \
  --set image.tag="${AGENT_IMAGE##*:}" \
  --set image.pullPolicy=IfNotPresent \
  --set config.tenantID="$ORG_ID" \
  --set config.controlPlane="http://$SERVER_SVC.${NAMESPACE}.svc:8080" \
  --set config.registrationToken="$REG_TOKEN" \
  --set config.clusterLabels="e2e=true" \
  --set oidcSecret.create=true \
  --set oidcSecret.secretStore=inari-platform \
  --set oidcSecret.remotePath="inari/clusters/${CLUSTER_ID#cluster:}/oidc-client-secret" \
  --wait --timeout 180s
# ESO wiring: the chart's opt-in ExternalSecret pulls from the
# ClusterSecretStore the registration response references
# (SecretDeliveryReference.esoSecretStore). ESO retries the ExternalSecret
# until the store exists, so this can be applied after the install.
kubectl -n inari-system create secret generic inari-vault-token \
  --from-literal=token="$VAULT_DEV_TOKEN" --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f - <<EOF
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata:
  name: inari-platform
spec:
  provider:
    vault:
      server: http://vault.${NAMESPACE}.svc:8200
      path: secret
      version: v2
      auth:
        tokenSecretRef:
          name: inari-vault-token
          namespace: inari-system
          key: token
EOF

log "waiting for registration, then the ESO-projected client secret"
for i in $(seq 1 24); do
  STATE=$(xcurl -H "Authorization: Bearer $(user_token)" "$API/tenants/$TENANT/clusters/$CLUSTER_ID" | jq -r '.cluster.state' 2>/dev/null || true)
  [ "$STATE" = "active" ] && break
  sleep 5
  [ "$i" = 24 ] && die "cluster never became active (agent logs: kubectl -n inari-system logs deploy/inari-agent)"
done
for i in $(seq 1 24); do
  kubectl -n inari-system get secret inari-agent-oidc-client >/dev/null 2>&1 && break
  sleep 5
  [ "$i" = 24 ] && die "ESO never projected inari-agent-oidc-client (kubectl -n inari-system get externalsecret inari-agent-oidc-client -o yaml)"
done
ESO_SECRET=$(kubectl -n inari-system get secret inari-agent-oidc-client -o jsonpath='{.data.client-secret}' | base64 -d)
KC_CLIENT_ID=$(xcurl -H "Authorization: Bearer $(user_token)" "$API/tenants/$TENANT/clusters/$CLUSTER_ID" | jq -r '.cluster.keycloakClientId')
AT="$(admin_token)"
KCID=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/clients?clientId=$KC_CLIENT_ID" | jq -r '.[0].id')
KC_SECRET=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/clients/$KCID/client-secret" | jq -r .value)
[ "$ESO_SECRET" = "$KC_SECRET" ] || die "ESO-projected secret does not match the Keycloak client secret"

log "verifying capabilities stream"
CAPS=0
for i in $(seq 1 36); do
  CAPS=$(xcurl -H "Authorization: Bearer $(user_token)" \
    "$API/tenants/$TENANT/clusters/$CLUSTER_ID/capabilities" | jq '.capabilities | length' 2>/dev/null || echo 0)
  [ "${CAPS:-0}" -gt 0 ] && break
  sleep 5
done
[ "${CAPS:-0}" -gt 0 ] || die "no capabilities streamed (agent logs: kubectl -n inari-system logs deploy/inari-agent)"

log "verifying heartbeat freshness"
SEEN1=$(xcurl -H "Authorization: Bearer $(user_token)" "$API/tenants/$TENANT/clusters/$CLUSTER_ID" | jq -r '.cluster.lastSeenAt')
sleep 30
SEEN2=$(xcurl -H "Authorization: Bearer $(user_token)" "$API/tenants/$TENANT/clusters/$CLUSTER_ID" | jq -r '.cluster.lastSeenAt')
[ "$SEEN1" != "$SEEN2" ] || die "heartbeat not advancing ($SEEN1)"

# --- RBAC mapping materialization (plan §7.1) -------------------------------
# tenant.created fired the materializer: <slug>-inari-state must appear as a
# real bare repo with baseline/rbac/* committed.
STATE_REPO="$GIT_HOST_DIR/$TENANT-inari-state.git"
log "waiting for the materialized tenant state repo ($STATE_REPO)"
for i in $(seq 1 36); do
  [ -d "$STATE_REPO" ] && git -C "$STATE_REPO" show main:baseline/rbac/clusterroles.yaml >/dev/null 2>&1 && break
  sleep 5
  [ "$i" = 36 ] && die "state repo never materialized (server logs: kubectl -n $NAMESPACE logs deploy/inari-server)"
done

# GAP(rbac-e2e-argocd): apply the repo's baseline/rbac/ from the host,
# standing in for the tenant-local ArgoCD (not installed in this stack).
STATE_WORK="$GIT_HOST_DIR/work"
sync_rbac() {
  rm -rf "$STATE_WORK"
  git clone -q "$STATE_REPO" "$STATE_WORK"
  kubectl apply -f "$STATE_WORK/baseline/rbac/" >/dev/null
  # Emulate ArgoCD's prune: drop managed bindings absent from the desired
  # set (a mapping flip renders a NEW role-qualified binding because
  # roleRef is immutable, so the stale object must be pruned to converge).
  for b in $(kubectl get clusterrolebinding -l "inari.io/tenant=$TENANT" -o name); do
    name="${b#clusterrolebinding.rbac.authorization.k8s.io/}"
    grep -qE "^  name: ${name}\$" "$STATE_WORK/baseline/rbac/clusterrolebindings.yaml" \
      || kubectl delete clusterrolebinding "$name" >/dev/null
  done
}

log "applying the materialized RBAC bundle and asserting the anchor roles"
sync_rbac
for ROLE in admin operator editor viewer; do
  kubectl get clusterrole "tenant-$TENANT-$ROLE" >/dev/null \
    || die "clusterrole tenant-$TENANT-$ROLE missing after sync"
done
kubectl get clusterrolebinding "tenant-$TENANT-viewers-viewer" >/dev/null \
  || die "clusterrolebinding tenant-$TENANT-viewers-viewer missing"
kubectl get clusterrolebinding "tenant-$TENANT-viewers-viewer" -o jsonpath='{.roleRef.name}' | grep -q "tenant-$TENANT-viewer" \
  || die "viewers binding roleRef is not tenant-$TENANT-viewer"

log "GAP(kc-groups-mapper): ensuring the groups claim carries full group paths"
AT="$(admin_token)"
MAPPERS=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/clients/$KC_CLIENT/protocol-mappers/models" | jq -r '.[].name')
if ! grep -q '^groups$' <<<"$MAPPERS"; then
  xcurl -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
    -d '{"name":"groups","protocol":"openid-connect","protocolMapper":"oidc-group-membership-mapper","config":{"claim.name":"groups","full.path":"true","id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true"}}' \
    -o /dev/null "http://keycloak-service:8080/admin/realms/inari/clients/$KC_CLIENT/protocol-mappers/models" \
    || die "failed to add the groups mapper"
fi

log "kubelogin-style check: group membership maps to real RBAC"
# A user in the viewers team group must read but not write.
log "ensuring the rbac-viewer Keycloak user"
VIEWER_UID=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/users?username=rbac-viewer" | jq -r '.[0].id // empty')
if [ -z "$VIEWER_UID" ]; then
  xcurl -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
    -d '{"username":"rbac-viewer","enabled":true,"emailVerified":true,"credentials":[{"type":"password","value":"rbac-viewer","temporary":false}]}' \
    -o /dev/null "http://keycloak-service:8080/admin/realms/inari/users"
  VIEWER_UID=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/users?username=rbac-viewer" | jq -r '.[0].id')
fi
# KC 26.x: create alone can leave the account unverified — force the final
# state, else the password grant fails with "Account is not fully set up".
xcurl -X PUT -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
  -d '{"email":"rbac-viewer@inari.local","emailVerified":true,"firstName":"RBAC","lastName":"Viewer","requiredActions":[],"enabled":true}' \
  -o /dev/null "http://keycloak-service:8080/admin/realms/inari/users/$VIEWER_UID"
log "adding rbac-viewer to the viewers team group"
VIEWERS_GRP=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/group-by-path/tenant-$TENANT/viewers" | jq -r '.id // empty')
[ -n "$VIEWERS_GRP" ] || die "Keycloak group tenant-$TENANT/viewers not found (tenant seeding broken?)"
xcurl -o /dev/null -X PUT -H "Authorization: Bearer $AT" \
  "http://keycloak-service:8080/admin/realms/inari/users/$VIEWER_UID/groups/$VIEWERS_GRP" || true

log "fetching the rbac-viewer token (groups claim only — the viewer is a group member, not a Keycloak Organization member, so the organization:* scope would be rejected)"
TOKEN_RESP=$(kubectl -n "$NAMESPACE" exec "$TOOLS" -- curl -s -m 20 \
  "http://keycloak-service:8080/realms/inari/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=inari-server \
  -d username=rbac-viewer -d password=rbac-viewer -d scope="openid")
VIEWER_TOKEN=$(jq -r '.access_token // empty' <<<"$TOKEN_RESP")
[ -n "$VIEWER_TOKEN" ] || die "rbac-viewer token request failed: $TOKEN_RESP"
PAYLOAD=$(cut -d. -f2 <<<"$VIEWER_TOKEN"); PAYLOAD="${PAYLOAD}$(printf '=%.0s' $(seq 1 $(( (4 - ${#PAYLOAD} % 4) % 4 ))))"
CLAIMS=$(base64 -d <<<"$PAYLOAD" 2>/dev/null || base64 -D <<<"$PAYLOAD")
jq -e --arg g "/tenant-$TENANT/viewers" '.groups and (.groups | index($g))' <<<"$CLAIMS" >/dev/null \
  || die "viewer token lacks the groups claim entry /tenant-$TENANT/viewers: $(jq -c .groups <<<"$CLAIMS")"

# RBAC authorizer check with the token's group (what the cluster would
# decide for this group once the API server trusts the Keycloak issuer —
# GAP(rbac-e2e-jwt-authn): wiring kind's kube-apiserver Authentication-
# Configuration to Keycloak is a follow-up).
kubectl auth can-i get pods --as="oidc:rbac-viewer" --as-group="/tenant-$TENANT/viewers" >/dev/null \
  || die "viewer group cannot get pods (binding not effective)"
if kubectl auth can-i create deployments --as="oidc:rbac-viewer" --as-group="/tenant-$TENANT/viewers" >/dev/null 2>&1; then
  die "viewer group can create deployments (viewer role over-privileged)"
fi

log "flipping the viewers team mapping to editor and expecting a binding update"
xcurl -X PUT -H "Authorization: Bearer $(user_token)" -H "Content-Type: application/json" \
  -d "{\"mappings\":[{\"team\":\"viewers\",\"role\":\"developer\"}]}" \
  "$API/tenants/$TENANT/rbac/mappings" >/dev/null || die "PUT rbac/mappings failed"
for i in $(seq 1 36); do
  if git -C "$STATE_REPO" show main:baseline/rbac/clusterrolebindings.yaml 2>/dev/null \
      | grep -qE "^  name: tenant-$TENANT-viewers-editor\$"; then
    break
  fi
  sleep 5
  [ "$i" = 36 ] && die "state repo binding never updated after the mapping change"
done
sync_rbac
kubectl get clusterrolebinding "tenant-$TENANT-viewers-editor" -o jsonpath='{.roleRef.name}' | grep -q "tenant-$TENANT-editor" \
  || die "viewers binding did not converge to tenant-$TENANT-editor"
if kubectl get clusterrolebinding "tenant-$TENANT-viewers-viewer" >/dev/null 2>&1; then
  die "stale viewers-viewer binding not pruned after the mapping change"
fi
kubectl auth can-i create deployments --as="oidc:rbac-viewer" --as-group="/tenant-$TENANT/viewers" >/dev/null \
  || die "editor-mapped group cannot create deployments after the mapping change"

# --- Policy evaluate matrix (issue #77) --------------------------------------
# deny-latest-image (target=request, Rego) must deny :latest and untagged
# images and allow pinned tags and digests via POST /policies/evaluate.
log "creating the deny-latest-image policy"
DENY_LATEST_REGO=$(cat <<'REGO'
package inari.policy

deny contains {"rule": "deny-latest-image", "reason": "image uses the :latest tag", "remediation": "pin an immutable tag or digest"} if {
	endswith(input.spec.image, ":latest")
}

deny contains {"rule": "deny-latest-image", "reason": "image has no tag or digest", "remediation": "pin an immutable tag or digest"} if {
	parts := split(input.spec.image, "/")
	last := parts[count(parts) - 1]
	not contains(last, ":")
	not contains(last, "@")
}
REGO
)
POLICY_RESP=$(kubectl -n "$NAMESPACE" exec "$TOOLS" -- curl -s -m 20 -X POST \
  -H "Authorization: Bearer $(user_token)" -H "Content-Type: application/json" \
  -d "$(jq -n --arg src "$DENY_LATEST_REGO" '{name:"deny-latest-image",target:"request",engine:"rego",source:$src}')" \
  "$API/tenants/$TENANT/policies")
POLICY_ID=$(jq -r '.policy.id // empty' <<<"$POLICY_RESP")
[ -n "$POLICY_ID" ] || die "policy creation failed: $POLICY_RESP"

eval_image() { # image -> evaluate response JSON
  kubectl -n "$NAMESPACE" exec "$TOOLS" -- curl -s -m 20 -X POST \
    -H "Authorization: Bearer $(user_token)" -H "Content-Type: application/json" \
    -d "$(jq -n --arg img "$1" --arg cid "$CLUSTER_ID" '{itemId:"demo",version:"1.0.0",clusterId:$cid,spec:{image:$img}}')" \
    "$API/tenants/$TENANT/policies/evaluate"
}

D=$(eval_image "ghcr.io/acme/app:latest")
jq -e '.decision.allow == false and ([.decision.violations[]?.rule] | index("deny-latest-image"))' <<<"$D" >/dev/null \
  || die ":latest image must be denied with a deny-latest-image violation: $D"
D=$(eval_image "ghcr.io/acme/app")
jq -e '.decision.allow == false' <<<"$D" >/dev/null \
  || die "untagged image must be denied: $D"
D=$(eval_image "registry:5000/acme/app")
jq -e '.decision.allow == false' <<<"$D" >/dev/null \
  || die "untagged image with a registry port must be denied: $D"
D=$(eval_image "ghcr.io/acme/app:1.4.2")
jq -e '.decision.allow == true and (.decision.violations | length == 0)' <<<"$D" >/dev/null \
  || die "pinned tag must be allowed: $D"
DIGEST="ghcr.io/acme/app@sha256:$(printf 'a%.0s' $(seq 1 64))"
D=$(eval_image "$DIGEST")
jq -e '.decision.allow == true and (.decision.violations | length == 0)' <<<"$D" >/dev/null \
  || die "digest-pinned image must be allowed: $D"

# Negative control: a disabled policy must not gate the request.
xcurl -X PUT -H "Authorization: Bearer $(user_token)" -H "Content-Type: application/json" \
  -d "$(jq -n --arg src "$DENY_LATEST_REGO" '{source:$src,enabled:false}')" \
  -o /dev/null "$API/tenants/$TENANT/policies/$POLICY_ID" || die "disabling the policy failed"
D=$(eval_image "ghcr.io/acme/app:latest")
jq -e '.decision.allow == true' <<<"$D" >/dev/null \
  || die "disabled policy must not deny: $D"
xcurl -X PUT -H "Authorization: Bearer $(user_token)" -H "Content-Type: application/json" \
  -d "$(jq -n --arg src "$DENY_LATEST_REGO" '{source:$src,enabled:true}')" \
  -o /dev/null "$API/tenants/$TENANT/policies/$POLICY_ID" || die "re-enabling the policy failed"

# ============================================================================
# HA-only disruption assertions (INARI_HA=true). Everything in this block
# runs ONLY in HA mode, after the golden path above has passed unchanged.
# ============================================================================
if $INARI_HA; then
  SERVER_LABEL=app.kubernetes.io/name=inari-server

  # start_traffic/stop_traffic: background availability sampler. It probes
  # /readyz through the ClusterIP Service from the toolbox pod — i.e. the
  # exact readiness-gated routing clients depend on — and records
  # ok=/fail= counts. Unauthenticated on purpose: Keycloak access tokens
  # can expire mid-disruption and would measure token lifetime, not API
  # availability. The sampler runs DETACHED inside the toolbox pod
  # (kubectl exec drops the stream once stdin EOFs, losing the tail of a
  # long-lived foreground sampler), writing its result to /tmp/traffic.out
  # which stop_traffic polls for. ≈5 iterations/s (busybox sh has no
  # SECONDS, so the window is an iteration count).
  kubectl -n "$NAMESPACE" exec -i "$TOOLS" -- sh -c 'cat > /tmp/sampler.sh && chmod +x /tmp/sampler.sh' <<'EOF'
#!/bin/sh
ok=0; fail=0; i=0
while [ "$i" -lt "$1" ]; do
  if curl -sf -m 5 -o /dev/null "$2"; then ok=$((ok+1)); else fail=$((fail+1)); fi
  i=$((i+1)); sleep 0.2
done
echo "ok=$ok fail=$fail"
EOF
  start_traffic() { # $1 = sample window in seconds
    kubectl -n "$NAMESPACE" exec "$TOOLS" -- sh -c \
      "rm -f /tmp/traffic.out; nohup /tmp/sampler.sh $(( $1 * 5 )) 'http://$SERVER_SVC:8080/readyz' > /tmp/traffic.out 2>&1 &"
  }
  stop_traffic() { # waits out the sampler, then prints "ok=N fail=M"
    local out=""
    for _ in $(seq 1 60); do
      out=$(kubectl -n "$NAMESPACE" exec "$TOOLS" -- cat /tmp/traffic.out 2>/dev/null || true)
      grep -q 'fail=' <<<"$out" && break
      sleep 3
    done
    echo "$out"
  }

  # ---------- HA(d1): leader-leased singleton loops run exactly once ------
  # ADR-0011: each lease-gated loop (approvals-expiry, the group syncs,
  # fleet loops, tzf-reconcile, ...) must have exactly one holder cluster-
  # wide, renewed (expires_at in the future), stable across samples (no
  # flapping), and — within this quiet window — acquired exactly once
  # since boot (no failover = the loop's effects ran on one pod only).
  log "HA(d1): leader-leased singleton loops — exactly one holder each, renewed and stable"
  LEASES=$(psql_inari "SELECT name || '|' || holder FROM leader_leases")
  [ -n "$LEASES" ] || die "HA(d1): leader_leases is empty (no lease-gated loop ever acquired?)"
  DUPES=$(cut -d'|' -f1 <<<"$LEASES" | sort | uniq -d)
  [ -z "$DUPES" ] || die "HA(d1): leases with duplicate holders: $DUPES"
  for sample in 1 2; do
    [ "$(psql_inari "SELECT count(*) FROM leader_leases WHERE name='approvals-expiry' AND expires_at > now()")" = "1" ] \
      || die "HA(d1): approvals-expiry lease missing or not renewed (sample $sample)"
    [ "$sample" = 1 ] && sleep 8
  done
  ACQ=$(kubectl -n "$NAMESPACE" logs -l "$SERVER_LABEL" --tail=-1 | grep -c 'leaderlease: acquired.*approvals-expiry' || true)
  [ "${ACQ:-0}" = "1" ] \
    || die "HA(d1): approvals-expiry leadership was acquired $ACQ times since boot, want exactly 1 (single-execution)"

  # ---------- HA(d2): agent stream fencing evicts stale sessions ----------
  # Fencing is per gateway instance (in-process session registry, W1), so
  # the duplicate stream must land on the SAME server pod as the live one.
  # Streams are per-connection load-balanced across the 2 server pods by
  # the ClusterIP, so 3 agent pods guarantee a collision by pigeonhole (3
  # streams, 2 pods) — deterministic, no luck involved. The new stream
  # wins; the stale session must be evicted (logged). Then scale back and
  # confirm the cluster returns to active.
  log "HA(d2): agent stream fencing — duplicate stream evicts the stale session"
  EVICTIONS_BEFORE=$(kubectl -n "$NAMESPACE" logs -l "$SERVER_LABEL" --tail=-1 | grep -c 'evicting stale session' || true)
  kubectl -n inari-system scale deployment/inari-agent --replicas=3 >/dev/null
  FENCED=false
  for i in $(seq 1 24); do
    EVICTIONS_NOW=$(kubectl -n "$NAMESPACE" logs -l "$SERVER_LABEL" --tail=-1 2>/dev/null | grep -c 'evicting stale session' || true)
    if [ "${EVICTIONS_NOW:-0}" -gt "${EVICTIONS_BEFORE:-0}" ]; then
      FENCED=true
      break
    fi
    sleep 5
  done
  kubectl -n inari-system scale deployment/inari-agent --replicas=1 >/dev/null
  kubectl -n inari-system rollout status deployment/inari-agent --timeout=180s >/dev/null
  [ "$FENCED" = "true" ] || die "HA(d2): no stale-session eviction was logged with 3 agent pods (fencing not exercised)"
  for i in $(seq 1 24); do
    STATE=$(xcurl -H "Authorization: Bearer $(user_token)" "$API/tenants/$TENANT/clusters/$CLUSTER_ID" | jq -r '.cluster.state' 2>/dev/null || true)
    [ "$STATE" = "active" ] && break
    sleep 5
    [ "$i" = 24 ] && die "HA(d2): cluster did not return to active after the agent scaled back to 1"
  done

  # ---------- HA(a): delete one server pod mid-run ------------------------
  # The surviving replica must keep serving (readiness-gated: zero failed
  # probes), and the claim-based loops (outbox dispatcher, scaffold
  # reconcile — deliberately NOT lease-gated, ADR-0011) must keep
  # processing work. Proven end-to-end: an RBAC mapping flip must still
  # materialize into the tenant state repo, and a fresh scaffold run must
  # still reach completed.
  log "HA(a): deleting one server pod mid-run — API stays available, outbox + scaffold reconcile continue"
  VICTIM=$(kubectl -n "$NAMESPACE" get pods -l "$SERVER_LABEL" -o jsonpath='{.items[0].metadata.name}')
  log "HA(a): victim pod: $VICTIM"
  start_traffic 90
  kubectl -n "$NAMESPACE" delete pod "$VICTIM" --wait=false
  kubectl -n "$NAMESPACE" rollout status deployment/inari-server --timeout=240s
  TRAFFIC=$(stop_traffic)
  FAILS=$(sed -n 's/.*fail=\([0-9]*\).*/\1/p' <<<"$TRAFFIC")
  [ "${FAILS:-99}" = "0" ] || die "HA(a): $FAILS failed requests while a pod was being replaced ($TRAFFIC)"
  xcurl -X PUT -H "Authorization: Bearer $(user_token)" -H "Content-Type: application/json" \
    -d "{\"mappings\":[{\"team\":\"viewers\",\"role\":\"org-admin\"}]}" \
    "$API/tenants/$TENANT/rbac/mappings" >/dev/null || die "HA(a): PUT rbac/mappings failed after the pod loss"
  for i in $(seq 1 36); do
    if git -C "$STATE_REPO" show main:baseline/rbac/clusterrolebindings.yaml 2>/dev/null \
        | grep -qE "^  name: tenant-$TENANT-viewers-admin\$"; then
      break
    fi
    sleep 5
    [ "$i" = 36 ] && die "HA(a): outbox dispatcher did not process rbac.mappings.updated after the pod loss"
  done
  log "HA(a): outbox dispatcher continued on the surviving pod; driving a scaffold run"
  # The go-service skeleton templates .Values.goVersion/.Values.port too;
  # the renderer does not inject schema defaults, so pass all four.
  RUN_RESP=$(xcurl -X POST -H "Authorization: Bearer $(user_token)" -H "Content-Type: application/json" \
    -d '{"values":{"serviceName":"ha-probe","module":"github.com/e2e/ha-probe","goVersion":"1.23","port":8080}}' \
    "$API/tenants/$TENANT/templates/go-service/runs")
  RUN_ID=$(jq -r '.run.id // empty' <<<"$RUN_RESP")
  [ -n "$RUN_ID" ] || die "HA(a): scaffold run creation failed: $RUN_RESP"
  for i in $(seq 1 48); do
    RUN_VIEW=$(xcurl -H "Authorization: Bearer $(user_token)" "$API/tenants/$TENANT/scaffold-runs/$RUN_ID" 2>/dev/null || true)
    PHASE=$(jq -r '.run.phase // empty' <<<"$RUN_VIEW")
    [ "$PHASE" = "completed" ] && break
    [ "$PHASE" = "failed" ] && die "HA(a): scaffold run failed post-disruption: $RUN_VIEW"
    sleep 5
    [ "$i" = 48 ] && die "HA(a): scaffold run stuck in phase '${PHASE:-unknown}' (reconcile loop not progressing on the survivor)"
  done

  # ---------- HA(b): rollout restart under traffic ------------------------
  # A full rolling restart must honor rollingUpdate.maxUnavailable: 0
  # (available replicas never drop below 2) and keep failed requests
  # within a small error budget (in-flight connections may reset during
  # pod termination).
  log "HA(b): rollout restart under traffic — maxUnavailable: 0, bounded error budget"
  AVAIL_LOG=$(mktemp /tmp/inari-e2e-avail.XXXXXX)
  echo 99 > "$AVAIL_LOG"
  start_traffic 150
  (
    for _ in $(seq 1 150); do
      AV=$(kubectl -n "$NAMESPACE" get deployment inari-server -o jsonpath='{.status.availableReplicas}' 2>/dev/null || true)
      # A transient kubectl/apiserver error yields an empty AV — skip the
      # sample rather than recording a bogus 0 as the minimum.
      case "$AV" in ''|*[!0-9]*) sleep 1; continue;; esac
      MIN=$(cat "$AVAIL_LOG")
      if [ "$AV" -lt "$MIN" ]; then echo "$AV" > "$AVAIL_LOG"; fi
      sleep 1
    done
  ) &
  WATCH_PID=$!
  kubectl -n "$NAMESPACE" rollout restart deployment/inari-server
  kubectl -n "$NAMESPACE" rollout status deployment/inari-server --timeout=300s
  wait "$WATCH_PID" 2>/dev/null || true
  TRAFFIC=$(stop_traffic)
  MIN_AVAIL=$(cat "$AVAIL_LOG")
  FAILS=$(sed -n 's/.*fail=\([0-9]*\).*/\1/p' <<<"$TRAFFIC")
  [ "$MIN_AVAIL" -ge 2 ] \
    || die "HA(b): availableReplicas dropped to $MIN_AVAIL during the rollout (maxUnavailable: 0 violated)"
  ERROR_BUDGET=2
  [ "${FAILS:-99}" -le "$ERROR_BUDGET" ] \
    || die "HA(b): $FAILS failed requests during the rollout restart, over the error budget of $ERROR_BUDGET ($TRAFFIC)"

  log "HA: all disruption assertions passed (c: migration-lock race, d1: lease single-execution, d2: stream fencing, a: pod kill, b: rollout restart)"
fi

HA_NOTE=""
$INARI_HA && HA_NOTE=" + HA disruption assertions (pod kill, rollout restart, migration-lock race, lease single-execution, stream fencing)"
log "PASS: golden path verified (tenant → register → stream → $CAPS capabilities → heartbeats → RBAC materialization → policy evaluate matrix)$HA_NOTE"
