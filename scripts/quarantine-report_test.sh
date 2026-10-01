#!/usr/bin/env bash
# quarantine-report_test.sh — tests for scripts/quarantine-report.sh.
# Uses a fake `gh` on PATH to capture issue create/comment calls.
# Run: scripts/quarantine-report_test.sh  (from anywhere)
set -euo pipefail

cd "$(dirname "$0")/.."

STUB=$(mktemp -d)
trap 'rm -rf "$STUB"' EXIT
mkdir -p "$STUB/bin"
: >"$STUB/gh-calls.log"

cat >"$STUB/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$GH_CALLS_LOG"
if [ "$1" = "issue" ] && [ "$2" = "list" ]; then
  case "$*" in
    *TestFailingWithExistingIssue*) list='[{"number": 42}]' ;;
    *) list='[]' ;;
  esac
  # Emulate gh's --jq '.[0].number' filter.
  case "$*" in
    *TestFailingWithExistingIssue*) echo "42" ;;
    *) echo "" ;;
  esac
fi
EOF
chmod +x "$STUB/bin/gh"

export GH_CALLS_LOG="$STUB/gh-calls.log"
export GH_TOKEN=test-token
export PATH="$STUB/bin:$PATH"

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

scripts/quarantine-report.sh scripts/testdata/quarantine/flaky-failures.xml \
  "https://github.com/7K-Inari/inari-server/actions/runs/12345" \
  >"$STUB/out.log" 2>&1 || { echo "report script failed:"; cat "$STUB/out.log"; exit 1; }

calls=$(cat "$GH_CALLS_LOG")

# One issue created for the new failing test...
check "creates issue for new failing test" \
  "1" \
  "$(grep -c 'issue create' <<<"$calls")"

check "created issue carries flaky-quarantine label + title" \
  "1" \
  "$(grep -c 'issue create.*Flaky quarantine: internal/tenancy/TestFailingNew.*flaky-quarantine' <<<"$calls")"

# ...and one comment on the already-existing issue (no duplicate issue).
check "comments on existing issue instead of creating a duplicate" \
  "1" \
  "$(grep -c 'issue comment 42' <<<"$calls")"

check "no issue for passing test" \
  "0" \
  "$(grep -c 'TestPassing' <<<"$calls")"

# Empty-failures JUnit -> no gh calls at all.
: >"$GH_CALLS_LOG"
scripts/quarantine-report.sh scripts/testdata/quarantine/flaky-clean.xml \
  "https://example.com/run" >"$STUB/out2.log" 2>&1
check "no gh calls when nothing failed" \
  "0" \
  "$(wc -l <"$GH_CALLS_LOG")"

if [ "$failures" -gt 0 ]; then
  echo "$failures test(s) FAILED" >&2
  exit 1
fi
echo "all quarantine-report tests passed"
