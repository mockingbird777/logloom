import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { gzipSync } from 'node:zlib';

const exec = promisify(execFile);
const project = fileURLToPath(new URL('..', import.meta.url));
const cli = join(project, 'dist', 'cli.js');
const fixture = join(project, 'test', 'fixtures', 'mixed.log');

test('CLI emits JSON to stdout', async () => {
  const { stdout, stderr } = await exec(process.execPath, [cli, 'analyze', fixture, '--format', 'json']);
  assert.equal(stderr, '');
  const report = JSON.parse(stdout);
  assert.equal(report.summary.linesRead, 11);
  assert.equal(report.summary.events, 11);
  assert.ok(report.privacy.redactions > 0);
});

test('--json - emits only JSON and no terminal summary', async () => {
  const { stdout, stderr } = await exec(process.execPath, [cli, fixture, '--json', '-']);
  assert.equal(stderr, '');
  const report = JSON.parse(stdout);
  assert.equal(report.schemaVersion, '1.0');
  assert.doesNotMatch(stdout, /Top templates/);
});

test('CLI writes a self-contained HTML report', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'logloom-'));
  const output = join(directory, 'report.html');
  const { stderr } = await exec(process.execPath, [cli, fixture, '--html', output, '--quiet']);
  assert.equal(stderr, '');
  const html = await readFile(output, 'utf8');
  assert.match(html, /<!doctype html>/);
  assert.match(html, /Private · offline/);
  assert.match(html, /window\.__LOGLOOM_REPORT__/);
});

test('CLI reports invalid flags with exit code 2', async () => {
  await assert.rejects(
    exec(process.execPath, [cli, fixture, '--wat']),
    (error) => error.code === 2 && /Unknown option/.test(error.stderr),
  );
});

test('CLI streams gzip-compressed logs', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'logloom-gzip-'));
  const archive = join(directory, 'mixed.log.gz');
  await writeFile(archive, gzipSync(await readFile(fixture)));
  const { stdout } = await exec(process.execPath, [cli, archive, '--format', 'json']);
  const report = JSON.parse(stdout);
  assert.equal(report.summary.linesRead, 11);
  assert.equal(report.metadata.source, 'mixed.log.gz');
});

test('CLI maps missing gzip input to exit code 2 without an unhandled error', async () => {
  const missing = join(tmpdir(), `logloom-missing-${process.pid}.log.gz`);
  await assert.rejects(
    exec(process.execPath, [cli, missing, '--format', 'json']),
    (error) => error.code === 2 && /ENOENT/.test(error.stderr) && !/Unhandled 'error'/.test(error.stderr),
  );
});

test('CLI bounds oversized lines before parsing and continues with the next line', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'logloom-large-'));
  const input = join(directory, 'large.log');
  await writeFile(input, `${'x'.repeat(2 * 1024 * 1024)}\n2026-07-19T10:00:00Z INFO survived\n`);
  const { stdout } = await exec(process.execPath, [cli, input, '--max-line-length', '1kb', '--format', 'json']);
  const report = JSON.parse(stdout);
  assert.equal(report.summary.linesRead, 2);
  assert.equal(report.summary.events, 2);
  assert.equal(report.summary.truncatedLines, 1);
  assert.ok(report.templates.some((template) => template.samples.includes('survived')));
});
