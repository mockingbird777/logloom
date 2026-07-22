# Changelog

All notable changes to LogLoom are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Opt-in `--precursors` analysis that links already-redacted, same-service source templates to their nearest subsequent error/fatal template and reports occurrences, support, support percentage, lift, and median gap.
- `--sequence-window <duration>` for configuring the precursor look-ahead window (default: five minutes).
- Schema `1.1` precursor output across terminal, JSON, and self-contained HTML reports; default analysis remains schema `1.0` with no sequence-state allocation.
- A bounded 100,000-event sequence store with explicit truncation metadata and notes, plus a programmatic `maxSequenceEvents` test boundary.

### Fixed

- Rejected overlong compressed IPv4-mixed IPv6 look-alikes instead of partially redacting them; explicit h16 groups on both sides of `::` are now jointly capped at five.

### Planned

- Configurable multiline stack-trace joining.
- Side-by-side report comparison.

## [0.2.0] - 2026-07-20

### Added

- `logloom demo`, a built-in synthetic incident that demonstrates redaction, template mining, error bursts, and latency regressions without requiring a log file.
- `--open` for launching a generated HTML investigation in the default browser.
- A report preview and copy-paste first-run path in the README.

## [0.1.0] - 2026-07-19

### Added

- Streaming file, gzip, and stdin ingestion.
- Per-line auto-detection for NDJSON/JSONL, logfmt, and common plain-text logs.
- Default-on redaction for likely secrets, tokens, credentials, emails, IPv4 addresses, private keys, and sensitive structured fields.
- Custom sensitive fields and regular-expression redaction rules.
- Drain-like streaming message-template clustering with bounded samples.
- Robust error-burst, template-frequency, and p95-latency anomaly signals.
- Bounded-memory latency p50, p95, and p99 estimates.
- Level, service, format, timeline, and template aggregations.
- Stable JSON report schema `1.0`.
- Self-contained interactive HTML report with chart, search, filters, sorting, anomaly cards, and JSON export.
- Automation-friendly CLI output and exit codes.
- Strict TypeScript build, Node test suite, continuous integration, and community health files.

[Unreleased]: https://github.com/mockingbird777/logloom/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mockingbird777/logloom/releases/tag/v0.2.0
[0.1.0]: https://github.com/mockingbird777/logloom/releases/tag/v0.1.0
