import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeLevel, parseLatency, parseLine, parseLogfmt } from '../dist/index.js';

test('parses structured NDJSON fields and latency', () => {
  const result = parseLine('{"@timestamp":"2026-07-19T10:00:00Z","severity":"ERROR","service":{"name":"billing"},"msg":"charge failed","latency":"1.25s"}');
  assert.equal(result.malformed, false);
  assert.equal(result.entry?.format, 'ndjson');
  assert.equal(result.entry?.timestamp?.toISOString(), '2026-07-19T10:00:00.000Z');
  assert.equal(result.entry?.level, 'error');
  assert.equal(result.entry?.service, 'billing');
  assert.equal(result.entry?.durationMs, 1250);
});

test('parses quoted logfmt values', () => {
  const fields = parseLogfmt('time=2026-07-19T10:00:00Z level=warn msg="slow request with spaces" duration=420ms');
  assert.deepEqual(fields, {
    time: '2026-07-19T10:00:00Z',
    level: 'warn',
    msg: 'slow request with spaces',
    duration: '420ms',
  });
  const result = parseLine('time=2026-07-19T10:00:00Z level=warn service=api msg="slow request" duration=420ms');
  assert.equal(result.entry?.message, 'slow request');
  assert.equal(result.entry?.durationMs, 420);
});

test('parses common plain logs', () => {
  const result = parseLine('2026-07-19T10:00:00Z ERROR [payments] gateway unavailable duration=920ms');
  assert.equal(result.entry?.level, 'error');
  assert.equal(result.entry?.service, 'payments');
  assert.match(result.entry?.message ?? '', /gateway unavailable/);
  assert.equal(result.entry?.durationMs, 920);
  const bracketed = parseLine('2026-07-19T10:00:01Z [WARN] [worker] retry scheduled');
  assert.equal(bracketed.entry?.level, 'warn');
  assert.equal(bracketed.entry?.service, 'worker');
  assert.equal(bracketed.entry?.message, 'retry scheduled');
  const embeddedFields = parseLine('2026-07-19T10:00:02Z ERROR [worker] failed token=secret-value duration=920ms');
  assert.equal(embeddedFields.entry?.format, 'plain');
  assert.equal(embeddedFields.entry?.level, 'error');
  assert.equal(embeddedFields.entry?.service, 'worker');
});

test('normalizes common levels and duration units', () => {
  assert.equal(normalizeLevel('CRITICAL'), 'fatal');
  assert.equal(normalizeLevel(40), 'warn');
  assert.equal(normalizeLevel('50'), 'error');
  assert.equal(parseLatency('250us'), 0.25);
  assert.equal(parseLatency('1.5s'), 1500);
  assert.equal(parseLine('INFO operation complete duration_s=1.5').entry?.durationMs, 1500);
});

test('does not duplicate structured records into the message fallback', () => {
  const result = parseLine('{"level":"info","token":"synthetic-sensitive-value"}');
  assert.equal(result.entry?.message, '(no message)');
  assert.equal(result.entry?.attributes.token, 'synthetic-sensitive-value');
});

test('marks malformed JSON-looking lines while preserving them as plain logs', () => {
  const result = parseLine('{definitely not json');
  assert.equal(result.malformed, true);
  assert.equal(result.entry?.format, 'plain');
  const array = parseLine('["not", "a", "log", "object"]');
  assert.equal(array.malformed, true);
  assert.equal(array.reason, 'JSON value is not an object');
});

test('does not auto-detect a partial or unterminated logfmt fragment', () => {
  const line = 'message="unterminated level=error service=api';
  assert.equal(parseLogfmt(line), undefined);
  const result = parseLine(line);
  assert.equal(result.entry?.format, 'plain');
  assert.equal(result.entry?.message, line);
});
