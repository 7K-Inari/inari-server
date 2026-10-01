#!/usr/bin/env bash
# quarantine-report.sh — open or update one GitHub issue per failing flaky-tagged
# test, from a gotestsum JUnit report.
#
# Usage:
#   scripts/quarantine-report.sh <junit.xml> <run-url>
#
# Idempotent by title: if an open issue labeled flaky-quarantine already exists
# whose title contains the test name, a comment is appended instead of creating
# a duplicate. Requires GH_TOKEN and `gh` on PATH. No-op when nothing failed.
set -euo pipefail

junit=${1:?usage: $0 <junit.xml> <run-url>}
run_url=${2:?usage: $0 <junit.xml> <run-url>}

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to parse $junit" >&2
  exit 1
fi

failures=$(python3 - "$junit" <<'PY'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
seen = set()
for suite in root.iter("testsuite"):
    name = suite.get("name", "")
    if "/internal/" in name:
        pkg = "internal/" + name.split("/internal/", 1)[1]
    else:
        pkg = name.rsplit("/", 1)[-1] if name else "unknown"
    suite_failed = False
    for case in suite.iter("testcase"):
        if case.find("failure") is None and case.find("error") is None:
            continue
        suite_failed = True
        test = case.get("name", "unknown")
        key = (pkg, test)
        if key in seen:
            continue
        seen.add(key)
        print(f"{pkg}/{test}")
    # Suite-level failure with no failing testcase (test-binary panic, build
    # failure of the test package): gotestsum records failures/errors on the
    # suite itself. File it under (suite) so a broken run is not silently
    # reported as "nothing to file".
    if not suite_failed:
        try:
            n = int(suite.get("failures", "0") or 0) + int(suite.get("errors", "0") or 0)
        except ValueError:
            n = 0
        if n > 0 and (pkg, "(suite)") not in seen:
            seen.add((pkg, "(suite)"))
            print(f"{pkg}/(suite)")
PY
)

if [ -z "$failures" ]; then
  echo "no flaky test failures in $junit — nothing to file"
  exit 0
fi

while IFS= read -r test_id; do
  title="Flaky quarantine: $test_id"
  # Quoted phrase + in:title so TestFoo does not match a TestFooBar issue.
  existing=$(gh issue list --label flaky-quarantine \
    --search "\"$test_id\" in:title" \
    --json number --jq '.[0].number' 2>/dev/null || true)
  body=$(cat <<EOF
**Flaky quarantine failure detected.**

- Test: \`$test_id\`
- Run: $run_url
- Last seen: $(date -u +%Y-%m-%dT%H:%M:%SZ)

Per the quarantine policy (see AGENTS.md), this issue must name an owner and
an expiry date (default ≤ 30 days) before the test can stay quarantined:

- Owner: <!-- required: @github-handle of the person fixing this -->
- Expiry: <!-- required: YYYY-MM-DD by which this is fixed or the test deleted -->
- Reason quarantined:
- Remediation notes:

Un-quarantine = remove the \`flaky\` build tag and reference this issue.
EOF
)
  if [ -n "$existing" ]; then
    echo "updating existing issue #$existing for $test_id"
    gh issue comment "$existing" --body "$body" || gh_rc=1
  else
    echo "filing new issue for $test_id"
    gh issue create --title "$title" --label flaky-quarantine --body "$body" || gh_rc=1
  fi
done <<<"$failures"

# A gh failure on one test must not starve the rest of the list (the loop
# always runs to completion); the step still exits non-zero so the workflow
# surfaces the partial failure.
exit "${gh_rc:-0}"
