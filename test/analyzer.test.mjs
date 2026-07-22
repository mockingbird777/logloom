import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLines, renderHtmlReport, renderJsonReport } from '../dist/index.js';

function event(timestamp, level, message, duration) {
  return JSON.stringify({ timestamp, level, service: 'api', message, duration_ms: duration });
}

function serviceEvent(timestamp, level, service, message) {
  return JSON.stringify({ timestamp, level, service, message });
}

test('clusters templates, computes quantiles, and detects bursts', async () => {
  const lines = [
    event('2026-07-19T10:00:01Z', 'info', 'request 100 completed', 100),
    event('2026-07-19T10:01:01Z', 'info', 'request 101 completed', 100),
    event('2026-07-19T10:02:01Z', 'info', 'request 102 completed', 100),
    ...Array.from({ length: 8 }, (_, i) => event(`2026-07-19T10:03:${String(i).padStart(2, '0')}Z`, i < 5 ? 'error' : 'info', `request ${200 + i} completed`, 600)),
  ];
  const report = await analyzeLines(lines, { source: 'memory', bucketMs: 60_000 });
  assert.equal(report.summary.events, 11);
  assert.equal(report.summary.errors, 5);
  assert.equal(report.summary.templates, 1);
  assert.equal(report.templates[0].template, 'request <num> completed');
  assert.equal(report.summary.latency?.p50Ms, 600);
  assert.ok(report.anomalies.some((item) => item.type === 'error-burst'));
  assert.ok(report.anomalies.some((item) => item.type === 'frequency-spike'));
  assert.ok(report.anomalies.some((item) => item.type === 'latency-spike'));
});

test('redacts before samples are retained and renders safe reports', async () => {
  const report = await analyzeLines([
    '{"timestamp":"2026-07-19T10:00:00Z","level":"info","message":"email x@example.com </script><script>alert(1)</script><img src=x onerror=alert(2)>","service":"api"}',
  ], { source: 'x@example.com/evil</title><script>sourceAttack()</script>&"' });
  assert.doesNotMatch(report.metadata.source, /x@example\.com/);
  assert.doesNotMatch(report.templates[0].samples[0], /x@example\.com/);
  const json = renderJsonReport(report);
  assert.equal(JSON.parse(json).schemaVersion, '1.0');
  const html = renderHtmlReport(report);
  assert.match(html, /window\.__LOGLOOM_REPORT__/);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.doesNotMatch(html, /<script>sourceAttack\(\)<\/script>/);
  assert.doesNotMatch(html, /<img src=x onerror/);
  assert.match(html, /\\u003c\/script\\u003e\\u003cscript\\u003ealert/);
  assert.match(html, /evil&amp;lt;\/title&amp;gt;|evil&lt;\/title&gt;/);
  const escapedTitle = 'LogLoom · [REDACTED:EMAIL]/evil&lt;/title&gt;&lt;script&gt;sourceAttack()&lt;/script&gt;&amp;&quot;';
  const description = 'Privacy-first, local-first log investigation with redaction, anomaly detection, and interactive reports.';
  assert.ok(html.includes(`<meta name="description" content="${description}">`));
  assert.ok(html.includes('<meta property="og:type" content="website">'));
  assert.ok(html.includes(`<meta property="og:title" content="${escapedTitle}">`));
  assert.ok(html.includes(`<meta property="og:description" content="${description}">`));
  assert.ok(html.includes('<meta name="twitter:card" content="summary">'));
  assert.ok(html.includes(`<meta name="twitter:title" content="${escapedTitle}">`));
  assert.ok(html.includes(`<meta name="twitter:description" content="${description}">`));
  assert.doesNotMatch(html, /(?:property|name)="og:image"/);
  assert.match(
    html,
    /<a href="https:\/\/github\.com\/mockingbird777\/logloom" target="_blank" rel="noopener noreferrer">Explore LogLoom on GitHub ↗<\/a>/,
  );
  assert.doesNotMatch(html, /<(?:script|img|link|iframe)\b[^>]*(?:src|href)="https?:\/\//i);
  assert.doesNotMatch(html, /(?:fetch\s*\(|XMLHttpRequest|sendBeacon)/);
});

test('accounts for malformed and empty lines', async () => {
  const report = await analyzeLines(['', '2026-07-19T10:00:00Z INFO hello', '{broken']);
  assert.equal(report.summary.linesRead, 3);
  assert.equal(report.summary.events, 2);
  assert.equal(report.summary.malformedLines, 1);
  assert.equal(report.timeline.length, 1);
});

test('keeps exact quantiles and avoids anomalies without three baseline buckets', async () => {
  const report = await analyzeLines([
    event('2026-07-19T10:00:01Z', 'info', 'first', 10),
    ...Array.from({ length: 5 }, (_, index) => event(`2026-07-19T10:01:0${index}Z`, 'error', 'second', 40)),
    event('2026-07-19T10:01:10Z', 'info', 'third', 20),
    event('2026-07-19T10:01:11Z', 'info', 'fourth', 30),
  ], { bucketMs: 60_000 });
  assert.equal(report.summary.latency?.p50Ms, 40);
  assert.deepEqual(report.anomalies, []);
});

test('removes absolute source and sample paths by default', async () => {
  const report = await analyzeLines([
    '2026-07-19T10:00:00Z INFO opened /Users/synthetic/private/credentials.txt',
  ], { source: '/Users/synthetic/private/app.log' });
  assert.equal(report.metadata.source, 'app.log');
  assert.doesNotMatch(report.templates[0].samples[0], /\/Users\/synthetic/);
  assert.match(report.templates[0].samples[0], /REDACTED:ABSOLUTE_PATH/);
});

test('keeps extreme finite latency values finite in JSON', async () => {
  const report = await analyzeLines([
    event('2026-07-19T10:00:01Z', 'info', 'extreme one', 1e308),
    event('2026-07-19T10:00:02Z', 'info', 'extreme two', 1e308),
  ]);
  assert.equal(Number.isFinite(report.summary.latency?.meanMs), true);
  assert.equal(Number.isFinite(report.summary.latency?.p95Ms), true);
  assert.doesNotMatch(renderJsonReport(report), /"(?:meanMs|p95Ms)": null/);
});

test('finds deterministic same-service failure precursors after sorting by timestamp', async () => {
  const lines = [];
  for (let minute = 0; minute < 4; minute += 1) {
    lines.push(serviceEvent(`2026-07-19T10:0${minute}:00Z`, 'warn', 'checkout', 'retry scheduled'));
    lines.push(serviceEvent(`2026-07-19T10:0${minute}:05Z`, 'error', 'checkout', 'gateway timeout'));
    lines.push(serviceEvent(`2026-07-19T10:0${minute}:06Z`, 'fatal', 'checkout', 'database crashed'));
  }
  for (let second = 10; second < 18; second += 1) {
    lines.push(serviceEvent(`2026-07-19T10:04:${second}Z`, 'info', 'checkout', `steady tick ${second}`));
  }

  const report = await analyzeLines(lines.reverse(), {
    precursors: true,
    sequenceWindowMs: 10_000,
  });

  assert.equal(report.schemaVersion, '1.1');
  assert.deepEqual(report.metadata.precursorAnalysis, {
    enabled: true,
    sequenceWindowMs: 10_000,
    maxSequenceEvents: 100_000,
    eventsSeen: 20,
    eventsRetained: 20,
    truncated: false,
  });
  assert.deepEqual(report.precursors, [{
    service: 'checkout',
    sourceTemplateId: report.precursors[0].sourceTemplateId,
    sourceTemplate: 'retry scheduled',
    failureTemplateId: report.precursors[0].failureTemplateId,
    failureTemplate: 'gateway timeout',
    occurrences: 4,
    support: 4,
    supportPercent: 100,
    lift: 3,
    medianGapMs: 5_000,
  }]);
  assert.ok(report.notes.some((note) => /not evidence of causality/.test(note)));
});

test('keeps precursor matching inside a redacted service boundary', async () => {
  const report = await analyzeLines([
    serviceEvent('2026-07-19T10:00:00Z', 'info', 'api', 'retry scheduled'),
    serviceEvent('2026-07-19T10:00:01Z', 'error', 'database', 'gateway timeout'),
    serviceEvent('2026-07-19T10:00:02Z', 'info', 'api', 'retry scheduled'),
    serviceEvent('2026-07-19T10:00:03Z', 'fatal', 'database', 'gateway timeout'),
  ], { precursors: true, sequenceWindowMs: 10_000 });
  assert.deepEqual(report.precursors, []);
});

test('filters candidates that have support but no lift over the service baseline', async () => {
  const report = await analyzeLines([
    serviceEvent('2026-07-19T10:00:00Z', 'info', 'api', 'retry scheduled'),
    serviceEvent('2026-07-19T10:00:01Z', 'error', 'api', 'gateway timeout'),
    serviceEvent('2026-07-19T10:00:02Z', 'info', 'api', 'retry scheduled'),
    serviceEvent('2026-07-19T10:00:03Z', 'error', 'api', 'gateway timeout'),
  ], { precursors: true, sequenceWindowMs: 10_000 });
  assert.deepEqual(report.precursors, []);
});

test('filters one-off precursor associations even when lift is high', async () => {
  const report = await analyzeLines([
    serviceEvent('2026-07-19T10:00:00Z', 'info', 'api', 'retry scheduled'),
    serviceEvent('2026-07-19T10:00:01Z', 'error', 'api', 'gateway timeout'),
    serviceEvent('2026-07-19T10:00:02Z', 'info', 'api', 'healthy now'),
  ], { precursors: true, sequenceWindowMs: 10_000 });
  assert.deepEqual(report.precursors, []);
});

test('discloses the programmatic sequence-event memory boundary', async () => {
  const report = await analyzeLines([
    serviceEvent('2026-07-19T10:00:00Z', 'info', 'api', 'one'),
    serviceEvent('2026-07-19T10:00:01Z', 'error', 'api', 'failure'),
    serviceEvent('2026-07-19T10:00:02Z', 'info', 'api', 'two'),
    serviceEvent('2026-07-19T10:00:03Z', 'error', 'api', 'failure'),
    serviceEvent('2026-07-19T10:00:04Z', 'info', 'api', 'three'),
  ], { precursors: true, maxSequenceEvents: 3 });
  assert.equal(report.metadata.precursorAnalysis?.eventsSeen, 5);
  assert.equal(report.metadata.precursorAnalysis?.eventsRetained, 3);
  assert.equal(report.metadata.precursorAnalysis?.truncated, true);
  assert.ok(report.notes.some((note) => /retained the first 3 of 5 timestamped events/.test(note)));
});

test('keeps schema 1.0 and allocates no precursor report fields by default', async () => {
  const report = await analyzeLines([event('2026-07-19T10:00:00Z', 'info', 'ready', 1)]);
  assert.equal(report.schemaVersion, '1.0');
  assert.equal('precursors' in report, false);
  assert.equal('precursorAnalysis' in report.metadata, false);
});

test('renders hostile precursor labels through escaped JSON and textContent', async () => {
  const service = 'api</script><img data-precursor src=x onerror=boom>';
  const source = 'retry </script><img data-source src=x onerror=boom>';
  const report = await analyzeLines([
    serviceEvent('2026-07-19T10:00:00Z', 'warn', service, source),
    serviceEvent('2026-07-19T10:00:01Z', 'error', service, 'gateway timeout'),
    serviceEvent('2026-07-19T10:00:10Z', 'warn', service, source),
    serviceEvent('2026-07-19T10:00:11Z', 'error', service, 'gateway timeout'),
    serviceEvent('2026-07-19T10:00:20Z', 'info', service, 'healthy now'),
    serviceEvent('2026-07-19T10:00:21Z', 'info', service, 'healthy now'),
  ], { precursors: true, sequenceWindowMs: 5_000 });
  const html = renderHtmlReport(report);
  assert.equal(report.precursors?.length, 1);
  assert.doesNotMatch(html, /<img data-(?:precursor|source)/);
  assert.match(html, /\\u003c\/script\\u003e\\u003cimg data-source/);
  assert.match(html, /source\.textContent=item\.sourceTemplate/);
  assert.match(html, /service\.textContent=item\.service/);
  assert.doesNotMatch(html, /innerHTML/);
});
