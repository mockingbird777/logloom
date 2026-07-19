# Contributing to LogLoom

Thanks for helping make local log investigation safer and more useful. Small, focused pull requests with realistic fixtures are especially valuable.

## Before you start

- Search existing issues and pull requests to avoid duplicating work.
- Open an issue before a large behavior or schema change so the design can be discussed.
- Never commit production logs, real credentials, personal data, or customer identifiers. Build the smallest synthetic fixture that demonstrates the behavior.
- Security vulnerabilities belong in the private process described in [SECURITY.md](SECURITY.md).

## Local setup

LogLoom requires Node.js 20 or newer.

```bash
git clone https://github.com/mockingbird777/logloom.git
cd logloom
npm install
npm test
```

Useful commands:

```bash
npm run build          # strict TypeScript compilation
npm test               # build and run all Node tests
npm run test:coverage  # built-in coverage report
npm run check          # tests and npm package dry run
```

## Project map

```text
src/parser.ts          line-level format detection and normalization
src/redactor.ts        default and custom privacy rules
src/cluster.ts         streaming message-template miner
src/anomaly.ts         robust bucket anomaly signals
src/analyzer.ts        streaming orchestration and aggregation
src/report/            JSON and standalone HTML renderers
src/cli.ts             argument parsing, I/O, and exit codes
test/                  unit and end-to-end tests
examples/              safe synthetic examples
```

## Change guidelines

### Parsers

Add a synthetic input and explicit assertions for timestamp, level, service, message, and duration behavior. A line that looks like malformed JSON must remain inspectable instead of disappearing silently.

### Redaction

Privacy rules run before retained samples or aggregates. New built-in expressions should be conservative, globally applied, and accompanied by positive and negative test cases. Do not paste a real credential into a fixture, even if it is revoked.

### Template mining and anomalies

Prefer deterministic, explainable behavior. Document threshold changes and add a fixture that demonstrates both the desired signal and a nearby non-signal. Avoid alerting on a single event.

### Report UI

The HTML output must remain one portable file with no remote scripts, fonts, images, analytics, or network requests. Put untrusted report values into `textContent`; never concatenate log values into HTML. Check narrow-screen behavior and keyboard focus.

### Public JSON schema

Treat `schemaVersion` as an API. Additive fields may ship in a minor release. Renames, removals, or semantic changes require a schema-version decision and migration notes.

## Pull requests

1. Branch from `main` and keep the change focused.
2. Add or update tests and documentation.
3. Run `npm run check` locally.
4. Complete the pull request template, including privacy and report-safety checks.
5. Use a clear imperative title, such as `Handle nested OpenTelemetry service names`.

By contributing, you agree that your contribution is licensed under the repository's MIT License and that you will follow the [Code of Conduct](CODE_OF_CONDUCT.md).
