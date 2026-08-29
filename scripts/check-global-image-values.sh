#!/usr/bin/env bash
# CI gate for the chart values contract (plan §4.2): render the chart with
# global.imageRegistry + global.imagePullSecrets set and fail if any rendered
# image reference ignores the registry, or any workload pod spec ignores the
# pull secrets.
#
# usage: check-global-image-values.sh <chart-dir> [extra helm template --set args]
set -euo pipefail

CHART="${1:?usage: check-global-image-values.sh <chart-dir> [extra --set args]}"
shift
REGISTRY="registry.ci-check.local:5000"
SECRET="ci-check-pull"
OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

helm template "$CHART" \
  --set "global.imageRegistry=${REGISTRY}" \
  --set "global.imagePullSecrets[0]=${SECRET}" \
  "$@" >"$OUT"

# Every image reference must be prefixed with the global registry.
if grep -E '^[[:space:]]+image: ' "$OUT" | grep -vqF "${REGISTRY}/"; then
  echo "ERROR: image reference(s) ignoring global.imageRegistry:" >&2
  grep -E '^[[:space:]]+image: ' "$OUT" | grep -vF "${REGISTRY}/" >&2
  exit 1
fi

# Every workload pod spec must carry the global pull secret.
awk -v secret="$SECRET" '
  /^---[[:space:]]*$/ { check(); kind="" }
  /^kind:[[:space:]]/ { kind=$2 }
  /imagePullSecrets:/ { hasips=1 }
  $0 ~ "name: \"" secret "\"" { hassecret=1 }
  END { check(); if (bad) exit 1 }
  function check() {
    if (kind ~ /^(Deployment|StatefulSet|DaemonSet|Job|CronJob|Keycloak)$/) {
      if (!hasips) {
        print "ERROR: " kind " pod spec missing imagePullSecrets" > "/dev/stderr"; bad=1
      } else if (!hassecret) {
        print "ERROR: " kind " pod spec ignores global.imagePullSecrets" > "/dev/stderr"; bad=1
      }
    }
    hasips=0; hassecret=0
  }
' "$OUT"

echo "global image values check passed for ${CHART}"
