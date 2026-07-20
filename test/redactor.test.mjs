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

test('redacts IPv6 addresses in full, compressed, loopback, and IPv4-mapped forms', () => {
  const redactor = new Redactor();
  const addresses = [
    '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
    '2001:db8::1',
    'fe80::1ff:fe23:4567:890a',
    '::1',
    '::ffff:192.0.2.1',
    '2001:DB8::A',
  ];
  for (const address of addresses) {
    const output = redactor.redactString(`peer connected from ${address} ok`);
    assert.equal(output.includes(address), false, address);
    assert.match(output, /\[REDACTED:IP\]/, address);
  }
});

test('redacts bracketed IPv6 host:port while preserving the port', () => {
  const redactor = new Redactor();
  assert.equal(
    redactor.redactString('upstream [2001:db8::1]:443 responded'),
    'upstream [[REDACTED:IP]]:443 responded',
  );
});

test('IPv4-mapped IPv6 is redacted whole, not left as a ::ffff: prefix', () => {
  const redactor = new Redactor();
  const output = redactor.redactString('src ::ffff:192.0.2.1 accepted');
  assert.equal(output, 'src [REDACTED:IP] accepted');
});

test('IPv6 counts under the existing IP category and respects disabling', () => {
  const redactor = new Redactor();
  redactor.redactString('from 2001:db8::1 and 203.0.113.7');
  const byType = Object.fromEntries(redactor.stats().byType.map((row) => [row.name, row.count]));
  assert.equal(byType.IP, 2);
  const disabled = new Redactor({}, false);
  assert.equal(disabled.redactString('2001:db8::1'), '2001:db8::1');
});

test('does not redact IPv6 look-alikes: timestamps, UUIDs, hashes, MACs, and C++ scopes', () => {
  const redactor = new Redactor();
  const negatives = [
    '2026-07-20T14:10:49Z',
    'at 12:34:56.789',
    'id 550e8400-e29b-41d4-a716-446655440000',
    'sha deadbeefcafe0123456789abcdef0123456789ab',
    'mac aa:bb:cc:dd:ee:ff',
    'calling std::vector::push_back',
    'ratio 1:2',
  ];
  for (const input of negatives) {
    assert.equal(redactor.redactString(input), input, input);
  }
});
