## What changed

<!-- Explain the user-visible outcome and why it belongs in LogLoom. -->

## How it was verified

<!-- Include commands, synthetic fixtures, and relevant output. -->

- [ ] `npm test`
- [ ] `npm run check`

## Privacy and compatibility

- [ ] No real logs, credentials, customer identifiers, or personal data are included.
- [ ] Retained messages are redacted before aggregation and rendering.
- [ ] Untrusted values in the HTML report use safe DOM APIs (`textContent`), not HTML concatenation.
- [ ] The report makes no external requests and remains self-contained.
- [ ] JSON schema changes are additive or explicitly versioned.
- [ ] CLI behavior, exit codes, and Node.js 20 support remain intentional.

## Documentation

- [ ] Tests cover the behavior or this change is documentation-only.
- [ ] README/CHANGELOG/examples were updated where needed.
