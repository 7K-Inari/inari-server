---
name: Flaky quarantine
about: Track a test quarantined behind the `flaky` build tag (H7 escape hatch)
title: "Flaky quarantine: <package>/<TestName>"
labels: [flaky-quarantine]
---

<!--
Quarantine policy (AGENTS.md): an owner and an expiry date are REQUIRED for a
test to stay quarantined. Default expiry is ≤ 30 days from quarantine; expired
quarantines are fixed or the test is deleted. Un-quarantine by removing the
`flaky` build tag and referencing this issue from the PR.
-->

- Test: <!-- e.g. internal/tenancy/TestFoo -->
- Quarantined since: <!-- YYYY-MM-DD -->
- Owner: <!-- REQUIRED: @github-handle of the person fixing this -->
- Expiry: <!-- REQUIRED: YYYY-MM-DD by which this is fixed or the test deleted -->
- Failure signature: <!-- error message / flake pattern that motivated quarantine -->
- Run where it last failed:
- Remediation notes: <!-- suspected root cause, fix direction -->
