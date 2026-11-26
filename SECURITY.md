# Security Policy

## Supported scope

Security reports are welcome for the maintained components in this repository, including the Telegram bots, API services, Docker configuration, and automation integrations.

## Reporting a vulnerability

**Do not report exploitable vulnerabilities in public issues, pull requests, discussions, or chat messages.**

Use GitHub's private vulnerability reporting flow from the repository's **Security** tab when it is enabled. If private reporting is unavailable, contact the repository maintainer privately through a verified contact method listed on the maintainer's GitHub profile. Include:

- A concise description and affected component.
- Reproduction steps or a minimal proof of concept.
- Potential impact and prerequisites.
- A suggested mitigation, if known.

Do not include real tokens, passwords, private keys, personal data, or production customer data in a report. Replace secrets with clearly fake placeholders.

## Response expectations

The maintainer will make a best-effort attempt to acknowledge reports, validate the issue, coordinate a fix, and publish an advisory when appropriate. Please allow time for remediation before public disclosure.

## Secrets and credential exposure

If a credential is exposed, revoke or rotate it immediately at its issuing provider. Removing it from Git history does not invalidate it. Review relevant service logs and access history for unexpected use.

## Safe testing

Only test systems and accounts you own or are explicitly authorized to assess. Avoid destructive testing, denial of service, persistence, and access to other users' data.
