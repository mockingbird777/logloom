# Security policy

LogLoom processes data that routinely contains credentials and personal information. We take report confidentiality, redaction bypasses, unsafe HTML rendering, path handling, and dependency integrity seriously.

## Supported versions

| Version | Security fixes |
|---|---|
| `0.2.x` | Supported |
| Older pre-release snapshots | Not supported |

Until LogLoom reaches `1.0`, security fixes are released on the latest minor version.

## Report a vulnerability privately

Please use **GitHub Security Advisories → Report a vulnerability** on this repository. Include:

- the affected version and operating system;
- a minimal synthetic input or proof of concept;
- the security impact and likely attack path;
- whether the issue involves redaction, generated HTML, CLI I/O, or packaging;
- any suggested mitigation.

Do not include real secrets, customer logs, or personal data. Do not open a public issue for an unpatched vulnerability.

We aim to acknowledge a report within 3 business days, provide an initial assessment within 7 business days, and coordinate a fix and disclosure timeline with the reporter. These are targets, not a contractual guarantee.

## Security boundaries

- Redaction is defense in depth, not a proof of anonymization. Custom formats may require custom rules.
- A generated report contains redacted message templates and samples. Treat it as potentially sensitive until reviewed.
- `--no-redact` intentionally removes the primary sharing safeguard.
- LogLoom does not sandbox input parsing. Run it with the permissions you would grant the input file itself.
- The standalone report performs no network requests, but opening it in a modified or untrusted browser environment is outside LogLoom's control.

## Safe disclosure

We welcome good-faith security research that avoids privacy violations, service disruption, destructive actions, and access to data you do not own. We will credit reporters who want attribution after a fix is available.
