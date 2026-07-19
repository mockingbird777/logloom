#!/usr/bin/env node
import { createReadStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createGunzip } from 'node:zlib';
import type { Readable } from 'node:stream';
import { basename } from 'node:path';
import { analyzeLines, type InputLine } from './analyzer.js';
import { renderHtmlReport } from './report/html.js';
import { renderJsonReport } from './report/json.js';
import type { AnalysisReport, RedactionConfig } from './types.js';
import { formatDuration, parseDuration, VERSION, writeFileAtomic } from './util.js';

type OutputFormat = 'summary' | 'json' | 'html';

interface CliOptions {
  input?: string;
  jsonPath?: string;
  htmlPath?: string;
  format: OutputFormat;
  bucketMs: number;
  redact: boolean;
  configPath?: string;
  maxLineLength: number;
  top: number;
  failOnAnomaly: boolean;
  quiet: boolean;
  help: boolean;
  version: boolean;
}

class UsageError extends Error {}

const HELP = `
LogLoom v${VERSION} — privacy-first local log investigation

Usage:
  logloom analyze [file|-] [options]
  cat app.log | logloom analyze [options]

Inputs:
  file                       NDJSON/JSONL, logfmt, plain text, or .gz file
  -                          read stdin explicitly (also the default when piped)

Outputs:
  --html <path>              write a self-contained interactive HTML report
  --json <path>              write a machine-readable JSON report (use - for stdout)
  --format <summary|json|html>
                             print this format to stdout (default: summary)

Analysis:
  --bucket <duration>        time bucket, e.g. 30s, 1m, 5m (default: 1m)
  --top <number>             templates shown in terminal summary (default: 10)
  --max-line-length <size>   truncate oversized lines, e.g. 2mb (default: 2mb)
  --fail-on-anomaly          exit 1 when an anomaly is detected

Privacy:
  --no-redact                disable default secret/PII redaction (use with care)
  --redaction-config <path>  JSON with sensitiveFields and custom regex patterns

Other:
  -q, --quiet                suppress terminal summary and write notices
  -h, --help                 show help
  -v, --version              show version

Exit codes: 0 success · 1 anomaly policy matched · 2 usage/input failure
`;

function takeValue(args: string[], index: number, flag: string): [string, number] {
  const value = args[index + 1];
  if (!value || value.startsWith('--')) throw new UsageError(`${flag} requires a value`);
  return [value, index + 1];
}

function parseByteSize(value: string): number {
  const match = /^(\d+(?:\.\d+)?)(b|kb|mb|gb)?$/i.exec(value.trim());
  if (!match?.[1]) throw new UsageError(`Invalid byte size: ${value}`);
  const amount = Number(match[1]);
  const unit = (match[2] ?? 'b').toLowerCase();
  const multiplier = unit === 'gb' ? 1024 ** 3 : unit === 'mb' ? 1024 ** 2 : unit === 'kb' ? 1024 : 1;
  const bytes = Math.floor(amount * multiplier);
  if (bytes < 1_024 || bytes > 1024 ** 3) throw new UsageError('--max-line-length must be between 1kb and 1gb');
  return bytes;
}

export function parseArguments(argv: string[]): CliOptions {
  const args = [...argv];
  if (args[0] === 'analyze') args.shift();
  const options: CliOptions = {
    format: 'summary',
    bucketMs: 60_000,
    redact: true,
    maxLineLength: 2 * 1024 * 1024,
    top: 10,
    failOnAnomaly: false,
    quiet: false,
    help: false,
    version: false,
  };
  const positionals: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg) continue;
    if (arg === '--') {
      positionals.push(...args.slice(index + 1));
      break;
    }
    if (arg === '-h' || arg === '--help') options.help = true;
    else if (arg === '-v' || arg === '--version') options.version = true;
    else if (arg === '-q' || arg === '--quiet') options.quiet = true;
    else if (arg === '--no-redact') options.redact = false;
    else if (arg === '--fail-on-anomaly') options.failOnAnomaly = true;
    else if (arg === '--json') {
      const [value, next] = takeValue(args, index, arg); options.jsonPath = value; index = next;
    } else if (arg === '--html') {
      const [value, next] = takeValue(args, index, arg); options.htmlPath = value; index = next;
    } else if (arg === '--format') {
      const [value, next] = takeValue(args, index, arg); index = next;
      if (!['summary', 'json', 'html'].includes(value)) throw new UsageError('--format must be summary, json, or html');
      options.format = value as OutputFormat;
    } else if (arg === '--bucket') {
      const [value, next] = takeValue(args, index, arg); index = next;
      try { options.bucketMs = parseDuration(value); } catch { throw new UsageError(`Invalid bucket duration: ${value}`); }
      if (options.bucketMs < 1_000) throw new UsageError('--bucket must be at least 1s');
    } else if (arg === '--top') {
      const [value, next] = takeValue(args, index, arg); index = next; options.top = Number(value);
      if (!Number.isInteger(options.top) || options.top < 1 || options.top > 1_000) throw new UsageError('--top must be an integer from 1 to 1000');
    } else if (arg === '--max-line-length') {
      const [value, next] = takeValue(args, index, arg); index = next; options.maxLineLength = parseByteSize(value);
    } else if (arg === '--redaction-config' || arg === '--config') {
      const [value, next] = takeValue(args, index, arg); options.configPath = value; index = next;
    } else if (arg.startsWith('-') && arg !== '-') throw new UsageError(`Unknown option: ${arg}`);
    else positionals.push(arg);
  }
  if (positionals.length > 1) throw new UsageError('Provide at most one input file');
  if (positionals[0] !== undefined) options.input = positionals[0];
  const stdoutOutputs = Number(options.jsonPath === '-') + Number(options.htmlPath === '-') + Number(options.format !== 'summary');
  if (stdoutOutputs > 1) throw new UsageError('Only one JSON or HTML output may target stdout');
  if (options.jsonPath && options.htmlPath && options.jsonPath !== '-' && options.jsonPath === options.htmlPath) {
    throw new UsageError('--json and --html must use different output paths');
  }
  return options;
}

async function loadRedactionConfig(path: string | undefined): Promise<RedactionConfig | undefined> {
  if (!path) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new UsageError(`Cannot read redaction config: ${messageOf(error)}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new UsageError('Redaction config must be a JSON object');
  return parsed as RedactionConfig;
}

function inputStream(path: string | undefined): { stream: Readable; source: string } {
  if (!path || path === '-') return { stream: process.stdin, source: 'stdin' };
  const file = createReadStream(path);
  if (path.toLowerCase().endsWith('.gz')) {
    const gunzip = createGunzip();
    file.on('error', (error) => gunzip.destroy(error));
    file.pipe(gunzip);
    return { stream: gunzip, source: path };
  }
  return { stream: file, source: path };
}

async function* boundedLines(stream: Readable, maxBytes: number): AsyncGenerator<InputLine> {
  let parts: Buffer[] = [];
  let bytes = 0;
  let truncated = false;
  let hasData = false;

  const append = (segment: Buffer): void => {
    if (segment.length === 0) return;
    hasData = true;
    const remaining = maxBytes - bytes;
    if (remaining > 0) {
      const kept = segment.subarray(0, remaining);
      parts.push(kept);
      bytes += kept.length;
    }
    if (segment.length > Math.max(remaining, 0)) truncated = true;
  };

  const finish = (): InputLine => {
    let buffer = Buffer.concat(parts, bytes);
    if (buffer.at(-1) === 0x0d) buffer = buffer.subarray(0, -1);
    const line: InputLine = truncated
      ? { text: buffer.toString('utf8'), truncated: true }
      : { text: buffer.toString('utf8') };
    parts = [];
    bytes = 0;
    truncated = false;
    hasData = false;
    return line;
  };

  for await (const rawChunk of stream) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(String(rawChunk));
    let offset = 0;
    while (offset < chunk.length) {
      const newline = chunk.indexOf(0x0a, offset);
      if (newline === -1) {
        append(chunk.subarray(offset));
        break;
      }
      append(chunk.subarray(offset, newline));
      yield finish();
      offset = newline + 1;
    }
  }
  if (hasData || truncated) yield finish();
}

function terminalSummary(report: AnalysisReport, top: number): string {
  const width = 72;
  const rows = [
    `LogLoom ${report.metadata.version}  ${report.metadata.source}`,
    '─'.repeat(width),
    `${report.summary.events.toLocaleString()} events  ·  ${report.summary.errors.toLocaleString()} errors (${report.summary.errorRate}%)  ·  ${report.summary.templates.toLocaleString()} templates`,
    `${report.summary.services.toLocaleString()} services  ·  ${report.anomalies.length.toLocaleString()} anomalies  ·  ${report.privacy.redactions.toLocaleString()} redactions`,
  ];
  if (report.summary.latency) rows.push(`Latency  p50 ${formatDuration(report.summary.latency.p50Ms)}  ·  p95 ${formatDuration(report.summary.latency.p95Ms)}  ·  p99 ${formatDuration(report.summary.latency.p99Ms)}`);
  rows.push('', 'Top templates');
  if (report.templates.length === 0) rows.push('  (no events)');
  report.templates.slice(0, top).forEach((template, index) => {
    const message = template.template.length > 49 ? `${template.template.slice(0, 46)}…` : template.template;
    rows.push(`${String(index + 1).padStart(2)}  ${String(template.count).padStart(7)}  ${String(template.errors).padStart(5)} err  ${message}`);
  });
  if (report.anomalies.length > 0) {
    rows.push('', 'Anomalies');
    report.anomalies.slice(0, 5).forEach((item) => rows.push(`  [${item.severity.toUpperCase()}] ${item.title} · ${item.timestamp}`));
  }
  rows.push('', `Analyzed in ${formatDuration(report.metadata.durationMs)} · redaction ${report.metadata.redactionEnabled ? 'on' : 'OFF'}`);
  return `${rows.join('\n')}\n`;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export async function runCli(argv = process.argv.slice(2)): Promise<number> {
  let options: CliOptions;
  try {
    options = parseArguments(argv);
  } catch (error) {
    process.stderr.write(`logloom: ${messageOf(error)}\nTry "logloom --help" for usage.\n`);
    return 2;
  }
  if (options.help) { process.stdout.write(HELP.trimStart()); return 0; }
  if (options.version) { process.stdout.write(`${VERSION}\n`); return 0; }
  if (!options.input && process.stdin.isTTY) {
    process.stderr.write('logloom: provide a log file or pipe logs on stdin\nTry "logloom --help" for usage.\n');
    return 2;
  }

  try {
    const config = await loadRedactionConfig(options.configPath);
    const input = inputStream(options.input);
    const lines = boundedLines(input.stream, options.maxLineLength);
    const analyzeOptions = {
      source: input.source,
      bucketMs: options.bucketMs,
      redact: options.redact,
      maxLineLength: options.maxLineLength,
      ...(config ? { redactionConfig: config } : {}),
    };
    const report = await analyzeLines(lines, analyzeOptions);
    const json = () => renderJsonReport(report);
    const html = () => renderHtmlReport(report);
    if (options.jsonPath) {
      if (options.jsonPath === '-') process.stdout.write(json());
      else { await writeFileAtomic(options.jsonPath, json()); if (!options.quiet) process.stderr.write(`JSON report → ${options.jsonPath}\n`); }
    }
    if (options.htmlPath) {
      if (options.htmlPath === '-') process.stdout.write(html());
      else { await writeFileAtomic(options.htmlPath, html()); if (!options.quiet) process.stderr.write(`HTML report → ${options.htmlPath}\n`); }
    }
    if (options.format === 'json') process.stdout.write(json());
    else if (options.format === 'html') process.stdout.write(html());
    else if (!options.quiet && options.jsonPath !== '-' && options.htmlPath !== '-') process.stdout.write(terminalSummary(report, options.top));
    return options.failOnAnomaly && report.anomalies.length > 0 ? 1 : 0;
  } catch (error) {
    process.stderr.write(`logloom: ${messageOf(error)}\n`);
    return 2;
  }
}

process.stdout.on('error', (error: NodeJS.ErrnoException) => {
  if (error.code === 'EPIPE') process.exit(0);
  throw error;
});

const invokedAsScript = process.argv[1] && basename(process.argv[1]).replace(/\.(?:js|ts)$/, '') === 'cli';
if (invokedAsScript || process.argv[1]?.endsWith('/logloom')) {
  void runCli().then((code) => { process.exitCode = code; });
}
