import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLines, renderHtmlReport, renderJsonReport } from '../dist/index.js';

function event(timestamp, level, message, duration) {
  return JSON.stringify({ timestamp, level, service: 'api', message, duration_ms: duration });
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
  assert.match(
    html,
    /<a href="https:\/\/github\.com\/mockingbird777\/logloom" target="_blank" rel="noopener noreferrer">Explore LogLoom on GitHub ↗<\/a>/,
  );
  assert.doesNotMatch(html, /<(?:script|img|link)\b[^>]*(?:src|href)="https?:\/\//i);
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
