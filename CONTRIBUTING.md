# Contributing to Inari

Thank you for contributing. Keep changes focused, follow the repository's existing conventions, and read `AGENTS.md` when present.

## Contribution Gate

Inari's hard gate G1 requires an approved Contributor License Agreement (CLA), an active CLA check, a security policy, a license, and the required trademark filing before external contributions are accepted.

**Current CLA status:** the agreement texts are drafts pending 7K Group owner and counsel approval. CLA assistant is not enabled, and external contributions remain paused until activation and completion of the other G1 items. Do not send signed agreements by email or attach them to issues or pull requests.

## How to Contribute

1. Search existing issues and pull requests. Discuss significant or hard-to-reverse changes before implementing them.
2. Create a focused branch and keep the diff reviewable.
3. Follow existing formatting and license-header conventions. Do not rewrite files solely to add license headers.
4. Add or update tests and documentation appropriate to the change.
5. Use Conventional Commits; release-please derives releases from commit messages. Do not edit generated changelogs or version numbers by hand.
6. Open a pull request targeting `main` and complete the required checks and review.

## Contributor License Agreement

Inari uses a CLA rather than a Developer Certificate of Origin (DCO). Contributors retain copyright. The CLA grants 7K Group broad non-exclusive rights, including sublicensing and future re-licensing rights; it is not a copyright assignment. A DCO `Signed-off-by` line does not replace the CLA.

The canonical agreements live only in `inari-docs`:

- [CLA policy and approval status](https://github.com/7K-Inari/inari-docs/blob/main/docs/legal/cla/README.md)
- [Individual Contributor License Agreement](https://github.com/7K-Inari/inari-docs/blob/main/docs/legal/cla/icla.md)
- [Corporate Contributor License Agreement](https://github.com/7K-Inari/inari-docs/blob/main/docs/legal/cla/ccla.md)

Use the individual agreement when you own the contribution yourself. If your employer or another legal entity owns it, an authorized representative must complete the corporate agreement on that entity's behalf.

### Digital Sign-off After Activation

1. Open a pull request. CLA assistant will comment when an agreement is required and provide a status check.
2. Follow the comment's link, authenticate with GitHub, review the applicable individual or corporate agreement, and select the click-through acceptance option.
3. Return to the pull request and confirm that the CLA status passes. All pull-request authors covered by the check must complete this flow.
4. When a materially revised CLA is published, follow the prompt to review and accept the new version.

No PDF, email, or manual `Signed-off-by` workflow is required. Maintainers can use the CLA assistant dashboard to review agreement versions and signing records without accepting signatures in repository files.

## License

Inari code, documentation, and community catalog content are currently distributed under [Apache License 2.0](LICENSE), unless a file explicitly states otherwise. The CLA preserves 7K Group's ability to use different outbound terms in the future; versions already distributed under Apache-2.0 remain available under that license.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting. Never disclose a vulnerability through a public contribution.
