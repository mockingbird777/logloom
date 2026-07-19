import test from 'node:test';
import assert from 'node:assert/strict';
import { Redactor } from '../dist/index.js';

test('redacts secrets, emails, IP addresses, and sensitive structured fields', () => {
  const redactor = new Redactor();
  const entry = redactor.redactEntry({
    level: 'info',
    message: 'login alice@example.com from 203.0.113.7:443 token=super-secret-value',
    service: 'api',
    attributes: { password: 'hunter2', nested: { authorization: 'Bearer abcdefghijklmnop' } },
    format: 'plain',
  });
  assert.doesNotMatch(entry.message, /alice@example\.com|203\.0\.113\.7|super-secret-value/);
  assert.match(entry.message, /\[REDACTED:IP\]:443/);
  assert.match(entry.message, /REDACTED:EMAIL/);
  assert.match(entry.message, /REDACTED:IP/);
  assert.equal(entry.attributes.password, '[REDACTED:FIELD]');
  assert.equal(entry.attributes.nested.authorization, '[REDACTED:FIELD]');
  assert.ok(redactor.stats().total >= 5);
});

test('supports custom patterns and can be disabled', () => {
  const custom = new Redactor({ patterns: [{ name: 'ORDER', regex: '\\bORD-[A-Z0-9]{8}\\b' }] });
  assert.equal(custom.redactString('created ORD-ABCD1234'), 'created [REDACTED:ORDER]');
  const disabled = new Redactor({}, false);
  assert.equal(disabled.redactString('alice@example.com'), 'alice@example.com');
});

test('covers common credential formats without retaining token bodies', () => {
  const redactor = new Redactor();
  const credentials = [
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl',
    'Bearer abcdefghijklmnopqrstuvwxyz.0123456789',
    ['AKIA', 'IOSFODNN7EXAMPLE'].join(''),
    ['ghp_', 'abcdefghijklmnopqrstuvwxyz123456'].join(''),
  ];
  const output = redactor.redactString(credentials.join(' '));
  credentials.forEach((credential) => assert.equal(output.includes(credential), false));
  assert.match(output, /REDACTED:JWT/);
  assert.match(output, /REDACTED:BEARER/);
  assert.match(output, /REDACTED:AWS_KEY/);
  assert.match(output, /REDACTED:GITHUB_TOKEN/);
});

test('redacts namespaced metadata fields, JSON-style secrets, and local paths', () => {
  const redactor = new Redactor();
  const value = redactor.redactEntry({
    level: 'info',
    message: 'payload {"token":"synthetic-sensitive-value"} at /Users/synthetic/private/file.log',
    service: 'api',
    attributes: {
      'http.request.header.authorization': 'Bearer synthetic-credential-value',
      headers: { 'x-api-key': 'synthetic-api-value' },
    },
    format: 'plain',
  });
  assert.doesNotMatch(value.message, /synthetic-sensitive-value|\/Users\/synthetic/);
  assert.equal(value.attributes['http.request.header.authorization'], '[REDACTED:FIELD]');
  assert.equal(value.attributes.headers['x-api-key'], '[REDACTED:FIELD]');
});
