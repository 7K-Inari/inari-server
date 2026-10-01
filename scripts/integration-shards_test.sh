#!/usr/bin/env bash
# integration-shards_test.sh — tests for scripts/integration-shards.sh.
# Run: scripts/integration-shards_test.sh  (from anywhere; no containers needed)
set -euo pipefail

cd "$(dirname "$0")/.."

SHARD_SCRIPT=scripts/integration-shards.sh
FIXTURES=scripts/testdata/integration-shards/junit
failures=0

check() { # <description> <expected> <actual>
  if [ "$2" == "$3" ]; then
    echo "ok: $1"
  else
    echo "FAIL: $1" >&2
    echo "  expected: $2" >&2
    echo "  actual:   $3" >&2
    failures=$((failures + 1))
  fi
}

# --- fallback: no junit dir -> identical to static map -----------------------
for shard in critical core-services modules-a modules-b; do
  check "balance falls back to static map for '$shard' (missing dir)" \
    "$("$SHARD_SCRIPT" packages "$shard")" \
    "$("$SHARD_SCRIPT" balance "$shard" /nonexistent-dir)"
done

# --- fallback: empty junit dir ----------------------------------------------
empty=$(mktemp -d)
trap 'rm -rf "$empty"' EXIT
check "balance falls back to static map (empty dir)" \
  "$("$SHARD_SCRIPT" packages core-services)" \
  "$("$SHARD_SCRIPT" balance core-services "$empty")"

# --- timing-based packing ----------------------------------------------------

# `gh run download` (no -n) unpacks each artifact into its own subdirectory;
# balance must find JUnit files in nested dirs and produce the same packing.
module_prefix="github.com/7K-Inari/inari-server"
nested=$(mktemp -d)
trap 'rm -rf "$empty" "$nested"' EXIT
mkdir -p "$nested/junit-integration-core-services"
cp "$FIXTURES"/*.xml "$nested/junit-integration-core-services/"
check "balance finds JUnit files in gh-style nested artifact dirs" \
  "$("$SHARD_SCRIPT" balance core-services "$FIXTURES")" \
  "$("$SHARD_SCRIPT" balance core-services "$nested")"

# gh run download (no -n) also fetches the junit-unit artifact, whose suite
# names are the same internal/... packages at unit-test scale. Unit timings
# must NOT overwrite integration timings (last-write-wins parse order).
mkdir -p "$nested/junit-unit"
cat >"$nested/junit-unit/unit-tests.xml" <<XML
<testsuites>
  <testsuite name="$module_prefix/internal/tenancy" tests="1" time="0.01"/>
  <testsuite name="$module_prefix/internal/scaffold" tests="1" time="0.01"/>
</testsuites>
XML
check "balance ignores junit-unit timings for shared packages" \
  "$("$SHARD_SCRIPT" balance core-services "$FIXTURES")" \
  "$("$SHARD_SCRIPT" balance core-services "$nested")"
for s in modules-a modules-b; do
  check "balance ignores junit-unit timings for '$s'" \
    "$("$SHARD_SCRIPT" balance "$s" "$FIXTURES")" \
    "$("$SHARD_SCRIPT" balance "$s" "$nested")"
done

# All-zero/negative/missing timings are not usable history: LPT loads never
# increase on ties, so every package would pile into the first bin. Must fall
# back to the static map instead.
zeros=$(mktemp -d)
cat >"$zeros/integration-zeros.xml" <<XML
<testsuites>
  <testsuite name="$module_prefix/internal/tenancy"/>
  <testsuite name="$module_prefix/internal/scaffold" time=""/>
  <testsuite name="$module_prefix/internal/cache" time="-5"/>
</testsuites>
XML
for s in core-services modules-a modules-b; do
  check "balance falls back to static map when all timings are zero ($s)" \
    "$("$SHARD_SCRIPT" packages "$s")" \
    "$("$SHARD_SCRIPT" balance "$s" "$zeros")"
done
rm -rf "$zeros"

# Every non-critical package in the static map, with a synthetic duration.
# critical shard must stay pinned to the static list.
non_critical=$(
  for s in core-services modules-a modules-b; do
    "$SHARD_SCRIPT" packages "$s"
  done | tr ' ' '\n' | sed 's|^\./||' | sort -u
)

# Union of all balanced output must equal the static union.
static_union=$(
  for s in critical core-services modules-a modules-b; do
    "$SHARD_SCRIPT" packages "$s"
  done | tr ' ' '\n' | sed 's|^\./||' | sort -u
)
balanced_union=$(
  for s in critical core-services modules-a modules-b; do
    "$SHARD_SCRIPT" balance "$s" "$FIXTURES"
  done | tr ' ' '\n' | sed 's|^\./||' | sort -u
)
check "balance covers the same package union as the static map" \
  "$static_union" "$balanced_union"

check "critical shard stays pinned to the static list" \
  "$("$SHARD_SCRIPT" packages critical)" \
  "$("$SHARD_SCRIPT" balance critical "$FIXTURES")"

# No duplicates across balanced shards.
all=$(
  for s in critical core-services modules-a modules-b; do
    "$SHARD_SCRIPT" balance "$s" "$FIXTURES"
  done | tr ' ' '\n' | grep -v '^$' | sort
)
dupes=$(uniq -d <<<"$all")
check "balance emits no duplicate packages" "" "$dupes"

# With fixture timings: heaviest package (internal/tenancy, 400s) must land
# in the first non-critical bin opened by LPT; bins must be load-balanced to
# within the heaviest remaining package (property check, not exact mapping).
sums=""
for s in core-services modules-a modules-b; do
  sum=$("$SHARD_SCRIPT" balance "$s" "$FIXTURES" | tr ' ' '\n' | while read -r pkg; do
    t=$(grep -ho "testsuite name=\"[^\"]*${pkg#./}\" [^>]*" "$FIXTURES"/*.xml | grep -o 'time="[0-9.]*"' | head -1 | tr -d 'time="')
    echo "${t:-0}"
  done | awk '{s+=$1} END {printf "%d", s}')
  sums="$sums $sum"
done
echo "fixture shard sums (core-services, modules-a, modules-b):$sums" >&2

# --- unknown shard still errors ----------------------------------------------
if "$SHARD_SCRIPT" balance bogus "$FIXTURES" >/dev/null 2>&1; then
  check "balance rejects unknown shard" "non-zero exit" "zero exit"
else
  check "balance rejects unknown shard" "non-zero exit" "non-zero exit"
fi

if [ "$failures" -gt 0 ]; then
  echo "$failures test(s) FAILED" >&2
  exit 1
fi
echo "all integration-shards tests passed"
