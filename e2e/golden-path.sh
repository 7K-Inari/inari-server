#!/usr/bin/env bash
# e2e golden path (CI gate): platform stack on kind → tenant → cluster
# registration → agent connect → capabilities streaming.
#
# Mirrors the manually validated flow. All HTTP calls run through a toolbox
# pod in the cluster (kubectl exec) so the script is immune to
# port-forward fragility. It intentionally performs a few Keycloak
# provisioning steps imperatively (org membership, client
# secret delivery) that are not yet automated in inari-server — each is
# marked GAP(n) and maps to a tracked upstream fix; the script must keep
# passing once those land.
#
# Prereqs: docker, kind, kubectl, helm, jq. Configurable via env:
#   CLUSTER_NAME (default inari-e2e)
#   SERVER_IMAGE / AGENT_IMAGE (default inari/server:e2e / inari/agent:e2e)
#   CHART_DIR (default ../inari-helm-charts/charts/inari-platform)
#   KEEP_CLUSTER=true to skip teardown
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-inari-e2e}"
SERVER_IMAGE="${SERVER_IMAGE:-inari/server:e2e}"
AGENT_IMAGE="${AGENT_IMAGE:-inari/agent:e2e}"
CHART_DIR="${CHART_DIR:-$(dirname "$0")/../../inari-helm-charts/charts/inari-platform}"
NAMESPACE="${NAMESPACE:-inari}"
TENANT="${TENANT:-e2e-org}"
KEEP_CLUSTER="${KEEP_CLUSTER:-false}"
TOOLS=golden-path-tools
KC_FQDN="keycloak-service.${NAMESPACE}.svc:8080"
SERVER_SVC="inari-inari-platform-server"

log() { printf '\033[1;34m[e2e]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[e2e] %s\033[0m\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "missing prerequisite: $1"; }
need docker; need kubectl; need helm; need jq; need kind

cleanup() {
  kubectl -n "$NAMESPACE" delete pod "$TOOLS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  $KEEP_CLUSTER || kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# xcurl runs curl inside the toolbox pod (never on the host).
xcurl() { kubectl -n "$NAMESPACE" exec "$TOOLS" -- curl -sf -m 20 "$@"; }

log "creating kind cluster '$CLUSTER_NAME'"
kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER_NAME" --wait 60s
kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null

log "loading images ($SERVER_IMAGE, $AGENT_IMAGE)"
kind load docker-image "$SERVER_IMAGE" "$AGENT_IMAGE" --name "$CLUSTER_NAME"

log "installing platform chart (corrected server env via values + extraEnv — GAP(chart-env))"
# The upstream chart template still ships stale env names (INARI_DATABASE_URI
# etc.); extraEnv supplies the real ones the server reads (last wins).
helm upgrade --install inari "$CHART_DIR" \
  --namespace "$NAMESPACE" --create-namespace \
  --set inariServer.enabled=true \
  --set inariServer.image.repository="${SERVER_IMAGE%:*}" \
  --set inariServer.image.tag="${SERVER_IMAGE##*:}" \
  --set inariServer.image.pullPolicy=IfNotPresent \
  --set inariServer.oidcIssuerUrl="http://$KC_FQDN/realms/inari" \
  --set inariServer.keycloakBaseUrl="http://$KC_FQDN" \
  --set-json "inariServer.extraEnv=[
    {\"name\":\"INARI_DATABASE_URL\",\"value\":\"postgres://inari:inari-dev@postgresql-rw:5432/inari?sslmode=disable\"},
    {\"name\":\"INARI_OIDC_ISSUER_URL\",\"value\":\"http://$KC_FQDN/realms/inari\"},
    {\"name\":\"INARI_KEYCLOAK_BASE_URL\",\"value\":\"http://$KC_FQDN\"},
    {\"name\":\"INARI_KEYCLOAK_ADMIN_USER\",\"value\":\"admin\"},
    {\"name\":\"INARI_KEYCLOAK_ADMIN_PASS\",\"value\":\"admin-dev\"},
    {\"name\":\"INARI_OPENFGA_API_URL\",\"value\":\"http://openfga:8080\"},
    {\"name\":\"INARI_AGENT_GATEWAY_ADDRESS\",\"value\":\"http://$SERVER_SVC.${NAMESPACE}.svc:8080\"},
    {\"name\":\"INARI_AGENT_IMAGE_REPO\",\"value\":\"inari/agent\"},
    {\"name\":\"INARI_AGENT_IMAGE_TAG\",\"value\":\"e2e\"}
  ]" \
  --wait --timeout 10m
kubectl -n "$NAMESPACE" rollout status deployment/inari-inari-platform-server --timeout=180s

log "starting toolbox pod"
kubectl -n "$NAMESPACE" delete pod "$TOOLS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
kubectl -n "$NAMESPACE" run "$TOOLS" --image=curlimages/curl:8.10.1 --restart=Never \
  --overrides='{"spec":{"securityContext":{"runAsUser":1000}}}' --command -- sleep 3600 >/dev/null
kubectl -n "$NAMESPACE" wait --for=condition=ready "pod/$TOOLS" --timeout=120s >/dev/null

log "pinning Keycloak hostname to the in-cluster FQDN (issuer consistency)"
# With a dynamic hostname, token issuers vary by request host and never match
# the server's configured issuer. The FQDN resolves from every namespace
# (server in $NAMESPACE, agent in inari-system). In production this is a real
# DNS name reachable from both sides.
kubectl -n "$NAMESPACE" wait --for=condition=complete job -l app.kubernetes.io/component=keycloak --timeout=300s 2>/dev/null || true
kubectl -n "$NAMESPACE" patch keycloak keycloak --type merge \
  -p "{\"spec\":{\"hostname\":{\"hostname\":\"http://$KC_FQDN\",\"strict\":true}}}"
kubectl -n "$NAMESPACE" rollout status statefulset/keycloak --timeout=420s
kubectl -n "$NAMESPACE" rollout status deployment/inari-inari-platform-server --timeout=180s || true
for i in $(seq 1 24); do
  ISS=$(xcurl "http://keycloak-service:8080/realms/inari/.well-known/openid-configuration" | jq -r .issuer 2>/dev/null || true)
  [ "$ISS" = "http://$KC_FQDN/realms/inari" ] && break
  sleep 5
  [ "$i" = 24 ] && die "issuer did not converge to $KC_FQDN (got: $ISS)"
done

admin_token() {
  xcurl "http://keycloak-service:8080/realms/master/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=admin-cli -d username=admin -d password=admin-dev \
    | jq -r .access_token
}
user_token() {
  xcurl "http://keycloak-service:8080/realms/inari/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=inari-server \
    -d username=dev-admin -d password=dev-admin -d scope="openid organization" \
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

log "creating tenant '$TENANT'"
API="http://$SERVER_SVC:8080/api/v1"
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
TEAM_ID=$(jq -r '.teams[] | select(.name=="platform-team") | .id' <<<"$TENANT_RESP")

log "GAP(org-membership): adding dev-admin to the Keycloak organization"
xcurl -X POST -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
  -d "\"$KC_UID\"" -o /dev/null \
  "http://keycloak-service:8080/admin/realms/inari/organizations/$ORG_KC_ID/members"

log "GAP(fga-membership): seeding platform-team membership tuple in OpenFGA"
FGA_STORE=$(xcurl "http://openfga:8080/stores" | jq -r '.stores[0].id')
xcurl -X POST "http://openfga:8080/stores/$FGA_STORE/write" -H "Content-Type: application/json" \
  -d "{\"writes\":{\"tuple_keys\":[{\"user\":\"user:$KC_UID\",\"relation\":\"member\",\"object\":\"team:$TEAM_ID\"}]}}" -o /dev/null
# The outbox dispatcher seeds the team→org role tuples asynchronously on the
# TenantCreated event — poll instead of racing it.
ALLOWED=false
for i in $(seq 1 18); do
  ALLOWED=$(xcurl -X POST "http://openfga:8080/stores/$FGA_STORE/check" -H "Content-Type: application/json" \
    -d "{\"tuple_key\":{\"user\":\"user:$KC_UID\",\"relation\":\"platform_engineer\",\"object\":\"organization:$ORG_KC_ID\"}}" | jq -r .allowed 2>/dev/null || echo false)
  [ "$ALLOWED" = "true" ] && break
  sleep 5
done
[ "$ALLOWED" = "true" ] || die "OpenFGA check failed after seeding tuples (dispatcher never seeded team→org roles)"

log "registering cluster + issuing token"
TOKEN="$(user_token)"
CLUSTER_RESP=$(xcurl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"e2e-self","labels":{"e2e":"true"}}' "$API/tenants/$TENANT/clusters")
CLUSTER_ID=$(jq -r '.cluster.id' <<<"$CLUSTER_RESP")

log "installing agent via the server-rendered manifest"
MANIFEST=$(mktemp)
trap 'rm -f "$MANIFEST"; cleanup' EXIT
xcurl -X POST -H "Authorization: Bearer $(user_token)" \
  "$API/tenants/$TENANT/clusters/$CLUSTER_ID/install-manifest" >"$MANIFEST"
kubectl apply -f "$MANIFEST"
kubectl -n inari-system rollout status deployment/inari-agent --timeout=180s

log "GAP(eso-secret): waiting for registration, then delivering the client secret"
for i in $(seq 1 24); do
  STATE=$(xcurl -H "Authorization: Bearer $(user_token)" "$API/tenants/$TENANT/clusters/$CLUSTER_ID" | jq -r '.cluster.state' 2>/dev/null || true)
  [ "$STATE" = "active" ] && break
  sleep 5
  [ "$i" = 24 ] && die "cluster never became active (agent logs: kubectl -n inari-system logs deploy/inari-agent)"
done
KC_CLIENT_ID=$(xcurl -H "Authorization: Bearer $(user_token)" "$API/tenants/$TENANT/clusters/$CLUSTER_ID" | jq -r '.cluster.keycloakClientId')
AT="$(admin_token)"
KCID=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/clients?clientId=$KC_CLIENT_ID" | jq -r '.[0].id')
CLIENT_SECRET=$(xcurl -H "Authorization: Bearer $AT" "http://keycloak-service:8080/admin/realms/inari/clients/$KCID/client-secret" | jq -r .value)
kubectl -n inari-system create secret generic inari-agent-oidc-client \
  --from-literal=client-secret="$CLIENT_SECRET" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n inari-system rollout restart deployment/inari-agent 2>/dev/null || true

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

log "PASS: golden path verified (tenant → register → stream → $CAPS capabilities → heartbeats)"
