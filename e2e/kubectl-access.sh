#!/usr/bin/env bash
# e2e kubectl access (plan §5.4, §7.2): a real kube-apiserver with structured
# JWT authentication (AuthenticationConfiguration) trusting a Keycloak
# realm, kubelogin exec plugin, tenant-scoped groups → ClusterRoles.
#
# Asserts the live contract:
#   - the token for a group member carries groups ["/tenant-acme/viewers"]
#     and an audience the API server accepts (the shape
#     tenancy.KubectlClientSpec emits: group-membership mapper full.path=true
#     + audience mapper kubernetes);
#   - kubectl get ns succeeds for a viewer-bound group;
#   - editor-only operations are denied.
#
# The scenario is control-plane-only by design: etcd + kube-apiserver +
# Keycloak as plain docker containers (no kubelet/containerd nesting), which
# is everything the authn/authz chain needs and works on hosts where kind/
# k3s cannot run. golden-path.sh remains the full-stack kind gate. Keycloak
# provisioning here mirrors tenancy.KubectlClientSpec (hub-side auto-
# provisioning is covered by unit + integration tests, EnsureKubectlClient);
# org-acme-kubectl gets directAccessGrantsEnabled=true as an e2e-only
# relaxation so kubelogin can run headless with --grant-type=password.
#
# Prereqs: docker, kubectl, jq, curl, openssl. Env: NETWORK, KC_IMAGE,
# APISERVER_IMAGE, ETCD_IMAGE, KEEP=true.
set -euo pipefail

NETWORK="${NETWORK:-inari-kubectl-e2e}"
KC_IMAGE="${KC_IMAGE:-quay.io/keycloak/keycloak:26.0}"
APISERVER_IMAGE="${APISERVER_IMAGE:-registry.k8s.io/kube-apiserver:v1.34.0}"
ETCD_IMAGE="${ETCD_IMAGE:-gcr.io/etcd-development/etcd:v3.5.21}"
TOOLS_IMAGE=curlimages/curl:8.10.1
KEEP="${KEEP:-false}"
KC_NAME="$NETWORK-keycloak"
ETCD_NAME="$NETWORK-etcd"
API_NAME="$NETWORK-apiserver"
TOOLS_NAME="$NETWORK-tools"
KC_HOST="keycloak:8443"
ISSUER="https://${KC_HOST}/realms/inari"
REALM=inari
ORG=acme
CLIENT_ID="org-${ORG}-kubectl"
GROUP_PATH="/tenant-${ORG}/viewers"
VIEWER_ROLE="tenant-${ORG}-viewer"
USERNAME=dev-viewer
PASSWORD=dev-viewer
WORKDIR_E2E="$(mktemp -d /tmp/inari-kubectl-e2e.XXXXXX)"

log() { printf '\033[1;34m[kubectl-e2e]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[kubectl-e2e] %s\033[0m\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "missing prerequisite: $1"; }
need docker; need kubectl; need jq; need curl; need openssl

cleanup() {
  if ! $KEEP; then
    docker rm -f "$TOOLS_NAME" "$API_NAME" "$KC_NAME" "$ETCD_NAME" >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
    rm -rf "$WORKDIR_E2E" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# xcurl runs curl inside the tools container (in-network DNS + CA trust).
xcurl() { docker exec "$TOOLS_NAME" curl -sf -m 30 --cacert /tmp/ca.crt "$@"; }

# --- 0. e2e PKI -------------------------------------------------------------
# One throwaway CA signs: the Keycloak TLS cert (embedded as the issuer CA
# in the AuthenticationConfiguration), the apiserver serving cert, and the
# admin client cert used for bootstrap.
log "generating e2e CA and certificates"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$WORKDIR_E2E/ca.key" -out "$WORKDIR_E2E/ca.crt" \
  -subj "/CN=inari-kubectl-e2e-ca" >/dev/null 2>&1
mkcert() { # name cn san
  openssl req -newkey rsa:2048 -nodes -keyout "$WORKDIR_E2E/$1.key" \
    -out "$WORKDIR_E2E/$1.csr" -subj "/CN=$2" >/dev/null 2>&1
  printf "subjectAltName=%s" "$3" > "$WORKDIR_E2E/$1.ext"
  openssl x509 -req -days 1 -in "$WORKDIR_E2E/$1.csr" \
    -CA "$WORKDIR_E2E/ca.crt" -CAkey "$WORKDIR_E2E/ca.key" -CAcreateserial \
    -out "$WORKDIR_E2E/$1.crt" -extfile "$WORKDIR_E2E/$1.ext" >/dev/null 2>&1
}
mkcert keycloak keycloak "DNS:keycloak"
mkcert apiserver kube-apiserver "DNS:kube-apiserver,DNS:localhost,IP:127.0.0.1"
# admin client cert (O=system:masters → full access for bootstrap)
openssl req -newkey rsa:2048 -nodes -keyout "$WORKDIR_E2E/admin.key" \
  -out "$WORKDIR_E2E/admin.csr" -subj "/CN=admin/O=system:masters" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$WORKDIR_E2E/admin.csr" \
  -CA "$WORKDIR_E2E/ca.crt" -CAkey "$WORKDIR_E2E/ca.key" -CAcreateserial \
  -out "$WORKDIR_E2E/admin.crt" >/dev/null 2>&1
# service-account signing key (required by kube-apiserver)
openssl genrsa -out "$WORKDIR_E2E/sa.key" 2048 >/dev/null 2>&1
openssl rsa -in "$WORKDIR_E2E/sa.key" -pubout -out "$WORKDIR_E2E/sa.pub" >/dev/null 2>&1

log "writing AuthenticationConfiguration (issuer $ISSUER)"
{
cat <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: ${ISSUER}
    certificateAuthority: |
EOF
sed 's/^/      /' "$WORKDIR_E2E/ca.crt"
cat <<EOF
    audiences:
    - kubernetes
    - ${CLIENT_ID}
    audienceMatchPolicy: MatchAny
  claimMappings:
    username:
      claim: preferred_username
      prefix: "keycloak:"
    groups:
      claim: groups
      prefix: ""
  claimValidationRules:
  # organization is multivalued in KC tokens (["acme"]); accept either form.
  - expression: 'has(claims.organization) && "${ORG}" in claims.organization'
    message: "token organization does not match this tenant"
EOF
} > "$WORKDIR_E2E/authn.yaml"

# --- 1. containers -----------------------------------------------------------
# Static IPs + --add-host: the daemon's embedded DNS (127.0.0.11) cannot be
# relied on in nested-daemon environments, so name resolution is pinned.
SUBNET=172.31.77.0/24
ETCD_IP=172.31.77.2
API_IP=172.31.77.3
KC_IP=172.31.77.4
TOOLS_IP=172.31.77.5

log "pulling images"
for img in "$ETCD_IMAGE" "$APISERVER_IMAGE" "$KC_IMAGE" "$TOOLS_IMAGE"; do
  docker pull -q "$img" >/dev/null
done
docker network create --subnet "$SUBNET" "$NETWORK" >/dev/null 2>&1 || true

log "starting etcd"
docker rm -f "$ETCD_NAME" >/dev/null 2>&1 || true
docker run -d --name "$ETCD_NAME" --network "$NETWORK" --ip "$ETCD_IP" --network-alias etcd \
  "$ETCD_IMAGE" /usr/local/bin/etcd \
  --advertise-client-urls http://etcd:2379 \
  --listen-client-urls http://0.0.0.0:2379 >/dev/null

log "starting kube-apiserver ($APISERVER_IMAGE, structured JWT authn)"
docker rm -f "$API_NAME" >/dev/null 2>&1 || true
docker create --name "$API_NAME" --network "$NETWORK" --ip "$API_IP" --network-alias kube-apiserver \
  --add-host "keycloak:$KC_IP" --add-host "etcd:$ETCD_IP" \
  "$APISERVER_IMAGE" \
  kube-apiserver \
  --etcd-servers=http://etcd:2379 \
  --authentication-config=/etc/k8s/authn.yaml \
  --authorization-mode=RBAC \
  --client-ca-file=/etc/k8s/ca.crt \
  --tls-cert-file=/etc/k8s/apiserver.crt \
  --tls-private-key-file=/etc/k8s/apiserver.key \
  --service-account-signing-key-file=/etc/k8s/sa.key \
  --service-account-key-file=/etc/k8s/sa.pub \
  --service-account-issuer=https://kubernetes.default.svc \
  --bind-address=0.0.0.0 \
  --allow-privileged=true >/dev/null
docker cp "$WORKDIR_E2E/." "$API_NAME:/etc/k8s/"
# NB: the apiserver is started only after realm provisioning (below) — its
# OIDC authenticator resolves the issuer discovery document at init time and
# a realm that does not exist yet races it.

log "starting Keycloak ($KC_IMAGE)"
docker rm -f "$KC_NAME" >/dev/null 2>&1 || true
docker create --name "$KC_NAME" --network "$NETWORK" --ip "$KC_IP" --network-alias keycloak \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_HOSTNAME="https://keycloak:8443" \
  -e KC_HTTPS_CERTIFICATE_FILE=/kc-tls.crt \
  -e KC_HTTPS_CERTIFICATE_KEY_FILE=/kc-tls.key \
  -e KC_HEALTH_ENABLED=true \
  "$KC_IMAGE" start-dev >/dev/null
docker cp "$WORKDIR_E2E/keycloak.crt" "$KC_NAME:/kc-tls.crt"
docker cp "$WORKDIR_E2E/keycloak.key" "$KC_NAME:/kc-tls.key"
docker start "$KC_NAME" >/dev/null

log "starting tools container"
docker rm -f "$TOOLS_NAME" >/dev/null 2>&1 || true
docker run -d --name "$TOOLS_NAME" --network "$NETWORK" --ip "$TOOLS_IP" --user 0 \
  --add-host "keycloak:$KC_IP" --add-host "kube-apiserver:$API_IP" \
  "$TOOLS_IMAGE" sleep 3600 >/dev/null
if [ ! -x "$WORKDIR_E2E/kubelogin" ]; then
  log "downloading kubelogin"
  KUBELOGIN_VERSION="${KUBELOGIN_VERSION:-v1.32.2}"
  curl -sfL -o "$WORKDIR_E2E/kubelogin.zip" \
    "https://github.com/int128/kubelogin/releases/download/${KUBELOGIN_VERSION}/kubelogin_linux_amd64.zip"
  if command -v unzip >/dev/null; then
    unzip -o -d "$WORKDIR_E2E" "$WORKDIR_E2E/kubelogin.zip" >/dev/null
  else
    python3 -c "import zipfile; zipfile.ZipFile('$WORKDIR_E2E/kubelogin.zip').extractall('$WORKDIR_E2E')"
  fi
fi
docker cp "$WORKDIR_E2E/kubelogin" "$TOOLS_NAME:/tmp/kubelogin"
docker cp "$WORKDIR_E2E/ca.crt" "$TOOLS_NAME:/tmp/ca.crt"
docker cp "$(command -v kubectl)" "$TOOLS_NAME:/tmp/kubectl"
docker exec "$TOOLS_NAME" chmod +x /tmp/kubelogin /tmp/kubectl
docker exec "$TOOLS_NAME" mkdir -p /tmp/bin
docker exec "$TOOLS_NAME" ln -sf /tmp/kubelogin /tmp/bin/kubectl-oidc_login

log "waiting for Keycloak https"
for i in $(seq 1 90); do
  xcurl "https://keycloak:8443/realms/master/.well-known/openid-configuration" >/dev/null 2>&1 && break
  sleep 4
  [ "$i" = 90 ] && { docker logs "$KC_NAME" 2>&1 | tail -10; die "keycloak never became ready"; }
done

# --- 2. Realm provisioning (mirrors tenancy.KubectlClientSpec) ---------------
ADMIN_TOKEN=$(xcurl "https://keycloak:8443/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli -d username=admin -d password=admin | jq -r .access_token)
[ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != null ] || die "keycloak admin token failed"
kc() { xcurl -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" "$@"; }

log "creating realm $REALM"
kc -X POST -d '{"realm":"'$REALM'","enabled":true,"organizationsEnabled":true}' -o /dev/null \
  "https://keycloak:8443/admin/realms" || true

log "creating organization $ORG + group $GROUP_PATH"
kc -X POST -d '{"name":"'$ORG'","alias":"'$ORG'","enabled":true,"domains":[{"name":"'$ORG'.local","verified":true}]}' -o /dev/null \
  "https://keycloak:8443/admin/realms/$REALM/organizations" || true
kc -X POST -d '{"name":"tenant-'$ORG'"}' -o /dev/null "https://keycloak:8443/admin/realms/$REALM/groups" || true
PARENT_ID=$(kc "https://keycloak:8443/admin/realms/$REALM/groups?exact=true&search=tenant-$ORG" | jq -r '.[0].id')
kc -X POST -d '{"name":"viewers"}' -o /dev/null \
  "https://keycloak:8443/admin/realms/$REALM/groups/$PARENT_ID/children" || true

log "creating user $USERNAME (org + group member)"
kc -X POST -d '{"username":"'$USERNAME'","enabled":true,"email":"'$USERNAME'@inari.local","emailVerified":true,"firstName":"Dev","lastName":"Viewer","requiredActions":[],
  "credentials":[{"type":"password","value":"'$PASSWORD'","temporary":false}]}' \
  -o /dev/null "https://keycloak:8443/admin/realms/$REALM/users" || true
UID_KC=$(kc "https://keycloak:8443/admin/realms/$REALM/users?username=$USERNAME" | jq -r '.[0].id')
# Belt and braces: reset-password is idempotent and survives a create that
# dropped the credentials block.
kc -X PUT -d '{"type":"password","value":"'$PASSWORD'","temporary":false}' -o /dev/null \
  "https://keycloak:8443/admin/realms/$REALM/users/$UID_KC/reset-password"
# Org-enabled realms attach required actions on new users; force final state.
kc -X PUT -d '{"enabled":true,"emailVerified":true,"firstName":"Dev","lastName":"Viewer","requiredActions":[]}' -o /dev/null \
  "https://keycloak:8443/admin/realms/$REALM/users/$UID_KC" || true
ORG_ID=$(kc "https://keycloak:8443/admin/realms/$REALM/organizations" | jq -r '.[0].id')
kc -X POST -d '"'"$UID_KC"'"' -o /dev/null "https://keycloak:8443/admin/realms/$REALM/organizations/$ORG_ID/members" || true
GROUP_ID=$(kc "https://keycloak:8443/admin/realms/$REALM/groups/$PARENT_ID/children?exact=true&search=viewers" | jq -r '.[0].id')
[ -n "$GROUP_ID" ] && [ "$GROUP_ID" != null ] || GROUP_ID=$(kc "https://keycloak:8443/admin/realms/$REALM/groups?search=viewers" | jq -r '.[] | select(.name=="viewers") | .id' | head -1)
kc -X PUT -o /dev/null "https://keycloak:8443/admin/realms/$REALM/users/$UID_KC/groups/$GROUP_ID" || true

log "creating client $CLIENT_ID (shape = tenancy.KubectlClientSpec; ROPC on for headless e2e)"
kc -X POST -d '{
  "clientId": "'$CLIENT_ID'",
  "name": "kubectl",
  "enabled": true,
  "publicClient": true,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "redirectUris": ["http://localhost:8000", "http://localhost:18000"],
  "attributes": {"oauth2.device.authorization.grant.enabled": "true"},
  "defaultClientScopes": ["openid", "profile", "basic", "organization"],
  "protocolMappers": [
    {"name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
     "config": {"claim.name": "groups", "full.path": "true", "id.token.claim": "true",
                "access.token.claim": "true", "userinfo.token.claim": "true"}},
    {"name": "audience-kubernetes", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
     "config": {"included.client.audience": "kubernetes", "id.token.claim": "false",
                "access.token.claim": "true", "userinfo.token.claim": "false"}}
  ]}' -o /dev/null "https://keycloak:8443/admin/realms/$REALM/clients" || true

# --- 3. API server + cluster-side RBAC (stands in for rbacmaterialize) ------
log "starting kube-apiserver (realm now exists; discovery will succeed)"
docker start "$API_NAME" >/dev/null
for i in $(seq 1 90); do
  docker exec "$TOOLS_NAME" curl -sk -m 5 https://kube-apiserver:6443/healthz 2>/dev/null | grep -q ok && break
  sleep 2
  [ "$i" = 90 ] && { docker logs "$API_NAME" 2>&1 | tail -10; die "kube-apiserver never became healthy"; }
done

log "applying ClusterRole $VIEWER_ROLE + binding for Group $GROUP_PATH"
cat > "$WORKDIR_E2E/admin.kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: e2e
  cluster:
    server: https://kube-apiserver:6443
    certificate-authority: /tmp/ca.crt
users:
- name: admin
  user:
    client-certificate: /tmp/admin.crt
    client-key: /tmp/admin.key
contexts:
- name: e2e
  context: {cluster: e2e, user: admin}
current-context: e2e
EOF
docker cp "$WORKDIR_E2E/admin.kubeconfig" "$TOOLS_NAME:/tmp/admin.kubeconfig"
docker cp "$WORKDIR_E2E/admin.crt" "$TOOLS_NAME:/tmp/admin.crt"
docker cp "$WORKDIR_E2E/admin.key" "$TOOLS_NAME:/tmp/admin.key"
ADMIN_K="docker exec -i $TOOLS_NAME env KUBECONFIG=/tmp/admin.kubeconfig /tmp/kubectl"
cat <<EOF | $ADMIN_K apply -f - >/dev/null
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${VIEWER_ROLE}
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: tenant-${ORG}-viewers-viewer
subjects:
- kind: Group
  name: "${GROUP_PATH}"
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: ${VIEWER_ROLE}
  apiGroup: rbac.authorization.k8s.io
EOF

# --- 4. kubelogin exec kubeconfig + assertions -------------------------------
log "building exec-credential kubeconfig in the tools container"
docker exec "$TOOLS_NAME" sh -c '
cat > /tmp/kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters:
- name: tenant
  cluster:
    server: https://kube-apiserver:6443
    certificate-authority: /tmp/ca.crt
users:
- name: tenant
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /tmp/kubectl
      args:
      - oidc-login
      - get-token
      - --oidc-issuer-url='"$ISSUER"'
      - --oidc-client-id='"$CLIENT_ID"'
      - --oidc-extra-scope=organization
      - --grant-type=password
      - --username='"$USERNAME"'
      - --password='"$PASSWORD"'
      interactiveMode: Never
      provideClusterInfo: true
contexts:
- name: tenant
  context: {cluster: tenant, user: tenant}
current-context: tenant
EOF'
# oidc-login resolves via the kubectl-<plugin> shim on PATH; SSL_CERT_FILE
# makes kubelogin trust the e2e CA.
EXEC_ENV="PATH=/tmp/bin:/usr/local/bin:/usr/bin:/bin KUBECONFIG=/tmp/kubeconfig SSL_CERT_FILE=/tmp/ca.crt"

log "asserting token claims (groups + audience)"
TOKEN_JSON=$(docker exec "$TOOLS_NAME" env $EXEC_ENV /tmp/kubectl oidc-login get-token \
  --oidc-issuer-url="$ISSUER" --oidc-client-id="$CLIENT_ID" --oidc-extra-scope=organization \
  --grant-type=password --username="$USERNAME" --password="$PASSWORD")
IDTOKEN=$(jq -r '.status.token // .status.idToken // empty' <<<"$TOKEN_JSON")
[ -n "$IDTOKEN" ] || die "kubelogin returned no token: $TOKEN_JSON"
PAYLOAD=$(cut -d. -f2 <<<"$IDTOKEN"); PAYLOAD="${PAYLOAD}$(printf '=%.0s' $(seq 1 $(( (4 - ${#PAYLOAD} % 4) % 4 ))))"
CLAIMS=$(base64 -d <<<"$PAYLOAD" 2>/dev/null || base64 -D <<<"$PAYLOAD")
jq -e --arg g "$GROUP_PATH" '.groups | index($g)' <<<"$CLAIMS" >/dev/null \
  || die "token missing groups claim $GROUP_PATH: $(jq -c .groups <<<"$CLAIMS")"
log "token groups = $(jq -c .groups <<<"$CLAIMS")"

log "asserting viewer can read namespaces"
docker exec "$TOOLS_NAME" env $EXEC_ENV /tmp/kubectl get ns >/dev/null \
  || die "kubectl get ns failed for viewer (should be allowed)"
log "kubectl get ns OK"

log "asserting editor-only ops are denied"
if docker exec "$TOOLS_NAME" env $EXEC_ENV /tmp/kubectl create namespace should-fail 2>/dev/null; then
  die "kubectl create namespace succeeded for viewer (should be denied)"
fi
CAN_I=$(docker exec "$TOOLS_NAME" env $EXEC_ENV /tmp/kubectl auth can-i create deployments -n default || true)
[ "$CAN_I" = "no" ] || die "auth can-i create deployments = $CAN_I, want no"
log "editor-only ops denied as expected"

log "ALL ASSERTIONS PASSED — kubectl access via kubelogin with tenant-scoped groups works"
