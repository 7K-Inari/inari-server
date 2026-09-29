#!/usr/bin/env bash
# resolve-edge-version.sh — resolve the edge version for a release-please
# manifest path.
#
# Usage: resolve-edge-version.sh <manifest-path>
#   <manifest-path>  key in .release-please-manifest.json (e.g. "." or
#                    "charts/inari-server")
#
# Resolution order:
#   1. The open release-please Release PR (label "autorelease: pending")
#      carries the pending versions in its bumped manifest — read
#      .release-please-manifest.json at the PR head ref and take the entry
#      for <manifest-path>.
#   2. Fallback: the working-tree manifest entry for <manifest-path> with a
#      patch bump (no Release PR open).
#   3. Repos without a manifest (release-please simple mode): the latest
#      stable (non-prerelease) v* tag with a patch bump.
#
# Output: <version>-<short-sha> (short sha from GITHUB_SHA or HEAD) — the
# immutable per-commit edge version; the moving `edge` channel tag is
# maintained separately by the edge workflows. Set RAW=1 to print only the
# base version.
#
# Requires: gh (GH_TOKEN), jq, git. Identical copy in every inari repo —
# keep in sync (see docs/ops/release-process.md).
set -euo pipefail

path="${1:?usage: resolve-edge-version.sh <manifest-path>}"
manifest=".release-please-manifest.json"

pending_version=""
pr_head=""
if [ -f "$manifest" ]; then
  pr_head="$(gh pr list --state open --label "autorelease: pending" \
    --json headRefName --limit 1 --jq '.[0].headRefName' 2>/dev/null || true)"
fi
if [ -n "$pr_head" ]; then
  pending_version="$(gh api "repos/${GITHUB_REPOSITORY}/contents/${manifest}?ref=${pr_head}" \
    --jq '.content' 2>/dev/null | tr -d '\n' | base64 -d | jq -r --arg p "$path" '.[$p] // empty' || true)"
fi

if [ -n "$pending_version" ]; then
  base="$pending_version"
elif [ -f "$manifest" ]; then
  current="$(jq -r --arg p "$path" '.[$p] // empty' "$manifest")"
  if [ -z "$current" ]; then
    echo "resolve-edge-version: no manifest entry for '$path'" >&2
    exit 1
  fi
  # Patch bump as the fallback next version.
  base="$(printf '%s\n' "$current" | awk -F. '{printf "%d.%d.%d", $1, $2, $3+1}')"
else
  # Simple mode (no manifest): latest stable tag + patch.
  current="$(git tag --list 'v*' --sort=-v:refname | grep -vE '^v[0-9]+\.[0-9]+\.[0-9]+-' | head -1 || true)"
  if [ -z "$current" ]; then
    # Unversioned repo (e.g. inari-docs): start the line at 0.1.0.
    echo "resolve-edge-version: no manifest and no stable v* tag — using 0.1.0" >&2
    base="0.1.0"
  else
    base="$(printf '%s\n' "${current#v}" | awk -F. '{printf "%d.%d.%d", $1, $2, $3+1}')"
  fi
fi

if [ "${RAW:-}" = "1" ]; then
  printf '%s\n' "$base"
  exit 0
fi

sha="${GITHUB_SHA:-$(git rev-parse HEAD)}"
printf '%s-%s\n' "$base" "${sha:0:7}"
