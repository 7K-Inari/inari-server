#!/usr/bin/env bash
# integration-shards.sh — shard map for the CI integration test matrix.
#
# Usage:
#   scripts/integration-shards.sh shards              # list shard names
#   scripts/integration-shards.sh packages <shard>    # space-separated package list
#   scripts/integration-shards.sh verify              # assert every package with
#                                                     # integration-tagged tests is
#                                                     # covered by exactly one shard
#
# Keep this map as the single source of truth for the shard split so rebalancing
# stays trivial (see plan: CI/testing restructure, risk 5).
set -euo pipefail

cd "$(dirname "$0")/.."

# Critical shard is always required (migrations, leader lease, outbox/eventbus,
# audit, authz, orchestrator, approvals). Long tail balanced by integration
# test file count.
CRITICAL="internal/db internal/leaderlease internal/eventbus internal/audit internal/authz internal/orchestrator internal/approvals"
CORE_SERVICES="internal/tenancy internal/scaffold"
MODULES_A="internal/policyservice internal/platformresources internal/extensionhost internal/agentgateway internal/usergit"
MODULES_B="internal/tenantzonefactory internal/secretstores internal/rbacmaterialize internal/notifications internal/fleetmanager internal/clusterregistry internal/cloudaccounts internal/catalog internal/cache"

all_shards() {
  echo "critical core-services modules-a modules-b"
}

# Emit ./-prefixed paths: bare "internal/db" is resolved by the go tool as an
# import path (module mode), not a directory, and fails with
# "package internal/db is not in std". See CI integration job.
packages() {
  local pkgs
  case "$1" in
    critical) pkgs=$CRITICAL ;;
    core-services) pkgs=$CORE_SERVICES ;;
    modules-a) pkgs=$MODULES_A ;;
    modules-b) pkgs=$MODULES_B ;;
    *) echo "unknown shard: $1 (expected: $(all_shards))" >&2; exit 1 ;;
  esac
  for p in $pkgs; do printf './%s ' "$p"; done
  echo
}

verify() {
  local actual expected covered dup missing rc=0
  # Every directory containing integration-tagged test files.
  actual=$(grep -rl --include='*_test.go' -e '^//go:build integration' internal/ \
    | xargs -n1 dirname | sort -u)
  # Every directory claimed by the shard map.
  expected=$(for s in $(all_shards); do for p in $(packages "$s"); do echo "${p#./}"; done; done | sort)

  covered=$(sort -u <<<"$expected")
  if [ "$(wc -l <<<"$expected")" != "$(wc -l <<<"$covered")" ]; then
    echo "duplicate packages in shard map:" >&2
    uniq -d <<<"$expected" >&2
    rc=1
  fi
  missing=$(comm -23 <(echo "$actual") <(echo "$covered"))
  if [ -n "$missing" ]; then
    echo "packages with integration tests missing from the shard map:" >&2
    echo "$missing" >&2
    rc=1
  fi
  extra=$(comm -13 <(echo "$actual") <(echo "$covered"))
  if [ -n "$extra" ]; then
    echo "shard map entries with no integration tests (fine, but drop to rebalance):" >&2
    echo "$extra" >&2
  fi
  if [ "$rc" -eq 0 ]; then
    echo "shard map covers all $(wc -l <<<"$actual") packages with integration-tagged tests"
  fi
  return $rc
}

cmd=${1:-}
case "$cmd" in
  shards) all_shards ;;
  packages) packages "${2:?usage: $0 packages <shard>}" ;;
  verify) verify ;;
  *) echo "usage: $0 {shards|packages <shard>|verify}" >&2; exit 2 ;;
esac
