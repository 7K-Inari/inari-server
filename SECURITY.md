# Security Policy

## Supported Versions

Inari is pre-v1 and uses release-please versioning. Only the latest minor release receives security fixes; older minor releases are not supported. Where a repository versions components independently, this policy applies to each component's latest minor release.

| Version | Security updates |
| --- | --- |
| Latest minor release | Yes |
| Older minor releases | No |
| Unreleased development branches | No |

## Reporting a Vulnerability

Report suspected vulnerabilities privately to [security@7kgroup.org](mailto:security@7kgroup.org). Do not open a public issue, discussion, or pull request for a security report.

Include the following information when possible:

- Affected repository and released version or commit.
- Potential impact and the conditions required to exploit the issue.
- Reproduction steps or a proof of concept that avoids real user data and production systems.
- Any known workaround or suggested mitigation.
- A safe way for us to contact you.

Please do not include secrets, personal data, or access to another user's environment in the report.

## Disclosure Process

1. The security team acknowledges the report and triages it privately. We may ask for additional details.
2. We investigate the affected supported release, develop and validate a fix, and determine whether an advisory is needed.
3. We coordinate the fixed release, advisory, and public disclosure timing with the reporter.
4. We credit the reporter when requested, unless they prefer to remain anonymous.

Please give us a reasonable opportunity to investigate and remediate before disclosing the issue publicly. If the issue is in a third-party project, report it to that project as well when appropriate; notify us privately when it creates a concrete risk in Inari.
