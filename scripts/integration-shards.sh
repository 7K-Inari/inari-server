#!/usr/bin/env bash
# integration-shards.sh — shard map for the CI integration test matrix.
#
# Usage:
#   scripts/integration-shards.sh shards                    # list shard names
#   scripts/integration-shards.sh packages <shard>          # static shard package list
#   scripts/integration-shards.sh balance <shard> <dir>     # timing-balanced package list
#                                                           # from gotestsum JUnit XML in <dir>
#                                                           # (falls back to the static map)
#   scripts/integration-shards.sh verify                    # assert every package with
#                                                           # integration-tagged tests is
#                                                           # covered by exactly one shard
#
# Keep the static map as the single source of truth for coverage so rebalancing
# stays trivial (see plan: CI/testing restructure, risk 5). `balance` only
# re-assigns packages among the non-critical shards by measured JUnit timing;
# the critical shard (race detector) stays pinned to the static list.
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

# balance <shard> <junit-dir>: emit a package list for <shard> balanced by
# measured per-package durations from gotestsum JUnit XML in <junit-dir>
# (CI downloads the previous successful run's junit-integration-* artifacts).
# The critical shard is pinned to the static list (it runs -race and must not
# absorb long-tail packages); all other packages are greedy LPT bin-packed into
# the remaining shards. Any failure (missing dir, unparsable XML, no timings,
# pack/set mismatch) falls back to the static map so CI never breaks on
# timing data alone.
balance() {
  local shard=$1 dir=${2:-}
  case "$shard" in
    critical|core-services|modules-a|modules-b) : ;;
    *) echo "unknown shard: $shard (expected: $(all_shards))" >&2; exit 1 ;;
  esac
  if [ "$shard" = "critical" ] || [ ! -d "$dir" ] || ! command -v python3 >/dev/null 2>&1; then
    packages "$shard"
    return
  fi
  # Static non-critical package pool per shard, for the packer + sanity check.
  local pools
  pools=$(
    for s in core-services modules-a modules-b; do
      printf '%s:' "$s"
      for p in $(packages "$s"); do printf '%s,' "${p#./}"; done
      echo
    done
  )
  local packed
  packed=$(POOLS="$pools" JUNIT_DIR="$dir" SHARD="$shard" python3 - <<'PY'
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

shard = os.environ["SHARD"]
pools = {}
for line in os.environ["POOLS"].splitlines():
    name, pkgs = line.split(":", 1)
    pools[name] = [p for p in pkgs.split(",") if p]
all_pool = [p for pkgs in pools.values() for p in pkgs]

# Per-package duration from every JUnit file; the latest value seen wins.
durations = {}
# `gh run download` (no -n) unpacks each artifact into its own subdirectory,
# so search recursively; flat dirs (fixtures, single-artifact downloads) work too.
for path in sorted(glob.glob(os.path.join(os.environ["JUNIT_DIR"], "**", "*.xml"), recursive=True)):
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        continue
    for suite in root.iter("testsuite"):
        name = suite.get("name", "")
        time = suite.get("time", "0") or "0"
        m = re.match(r".*?/internal/(.+)$", name)
        if not m:
            continue
        pkg = "internal/" + m.group(1)
        if pkg in all_pool:
            try:
                durations[pkg] = float(time)
            except ValueError:
                pass

if not durations:
    sys.exit(3)

# Greedy LPT bin-packing over the union pool into the non-critical shards.
# Total order on (-duration, pkg) so ties are deterministic across processes
# (set iteration order is hash-randomized).
bin_names = list(pools.keys())
bins = {name: [] for name in bin_names}
loads = {name: 0.0 for name in bin_names}
for pkg in sorted(set(all_pool), key=lambda p: (-durations.get(p, 0.0), p)):
    target = min(bin_names, key=lambda b: loads[b])
    bins[target].append(pkg)
    loads[target] += durations.get(pkg, 0.0)

# Sanity: the packed set must equal the static union (coverage preserved).
if sorted(p for pkgs in bins.values() for p in pkgs) != sorted(set(all_pool)):
    sys.exit(4)

for pkg in sorted(bins[shard]):
    print("./" + pkg)
PY
) || { packages "$shard"; return; }
  if [ -z "$packed" ]; then
    packages "$shard"
    return
  fi
  echo "$packed" | tr '\n' ' '
  echo
}

cmd=${1:-}
case "$cmd" in
  shards) all_shards ;;
  packages) packages "${2:?usage: $0 packages <shard>}" ;;
  balance) balance "${2:?usage: $0 balance <shard> <junit-dir>}" "${3:-}" ;;
  verify) verify ;;
  *) echo "usage: $0 {shards|packages <shard>|balance <shard> <junit-dir>|verify}" >&2; exit 2 ;;
esac
