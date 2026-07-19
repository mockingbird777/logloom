import type { InputFormat, LogLevel, ParseResult, ParsedEntry } from './types.js';

const TIMESTAMP_KEYS = ['timestamp', 'time', 'ts', '@timestamp', 'datetime', 'date'];
const LEVEL_KEYS = ['level', 'severity', 'loglevel', 'log_level'];
const MESSAGE_KEYS = ['message', 'msg', 'event', 'log', 'text'];
const SERVICE_KEYS = ['service', 'service.name', 'service_name', 'app', 'application', 'component', 'logger'];
const DURATION_KEYS = ['duration', 'duration_ms', 'durationms', 'latency', 'latency_ms', 'latencyms', 'elapsed', 'elapsed_ms', 'response_time', 'response_time_ms'];

const LEVEL_ALIASES: Record<string, LogLevel> = {
  trace: 'trace',
  verbose: 'trace',
  debug: 'debug',
  info: 'info',
  notice: 'info',
  warn: 'warn',
  warning: 'warn',
  error: 'error',
  err: 'error',
  fatal: 'fatal',
  critical: 'fatal',
  crit: 'fatal',
  emergency: 'fatal',
  emerg: 'fatal',
  alert: 'fatal',
};

export function normalizeLevel(value: unknown): LogLevel {
  if (typeof value === 'number') {
    if (value >= 60) return 'fatal';
    if (value >= 50) return 'error';
    if (value >= 40) return 'warn';
    if (value >= 30) return 'info';
    if (value >= 20) return 'debug';
    if (value >= 10) return 'trace';
  }
  const normalized = String(value ?? '').trim().toLowerCase();
  if (/^\d+(?:\.\d+)?$/.test(normalized)) return normalizeLevel(Number(normalized));
  return LEVEL_ALIASES[normalized] ?? 'unknown';
}

export function parseTimestamp(value: unknown, now = new Date()): Date | undefined {
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value;
  if (typeof value === 'number' && Number.isFinite(value)) {
    const milliseconds = value < 10_000_000_000 ? value * 1_000 : value;
    const date = new Date(milliseconds);
    return Number.isNaN(date.getTime()) ? undefined : date;
  }
  if (typeof value !== 'string' || value.trim() === '') return undefined;
  const text = value.trim().replace(/^\[|\]$/g, '');
  if (/^\d{10}(?:\.\d+)?$/.test(text)) return parseTimestamp(Number(text), now);
  if (/^\d{13}$/.test(text)) return parseTimestamp(Number(text), now);
  const syslog = /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$/i.exec(text);
  const candidate = syslog ? `${syslog[1]} ${syslog[2]} ${now.getFullYear()} ${syslog[3]}` : text;
  const milliseconds = Date.parse(candidate);
  return Number.isNaN(milliseconds) ? undefined : new Date(milliseconds);
}

export function parseLatency(value: unknown, key = ''): number | undefined {
  if (typeof value === 'number') return Number.isFinite(value) && value >= 0 ? value : undefined;
  if (typeof value !== 'string') return undefined;
  const match = /^\s*(\d+(?:\.\d+)?)\s*(ns|us|µs|μs|ms|s|sec|secs|seconds)?\s*$/i.exec(value);
  if (!match) return undefined;
  const amount = Number(match[1]);
  if (!Number.isFinite(amount)) return undefined;
  const unit = (match[2] ?? (key.toLowerCase().endsWith('_s') ? 's' : 'ms')).toLowerCase();
  if (unit === 'ns') return amount / 1_000_000;
  if (unit === 'us' || unit === 'µs' || unit === 'μs') return amount / 1_000;
  if (unit === 's' || unit.startsWith('sec')) return amount * 1_000;
  return amount;
}

function findEntry(record: Record<string, unknown>, names: string[]): [string, unknown] | undefined {
  const wanted = new Set(names.map((name) => name.toLowerCase()));
  for (const [key, value] of Object.entries(record)) {
    if (wanted.has(key.toLowerCase())) {
      if (key.toLowerCase() === 'service' && names.includes('service.name') && value && typeof value === 'object' && !Array.isArray(value)) {
        const nestedName = (value as Record<string, unknown>)['name'];
        if (nestedName !== undefined) return ['service.name', nestedName];
      }
      return [key, value];
    }
  }
  const nested = record['service'];
  if (names.includes('service.name') && nested && typeof nested === 'object' && !Array.isArray(nested)) {
    const name = (nested as Record<string, unknown>)['name'];
    if (name !== undefined) return ['service.name', name];
  }
  return undefined;
}

function safeString(value: unknown, fallback: string): string {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return fallback;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return String(value);
  return fallback;
}

function fromRecord(record: Record<string, unknown>, format: InputFormat): ParsedEntry {
  const timestampEntry = findEntry(record, TIMESTAMP_KEYS);
  const levelEntry = findEntry(record, LEVEL_KEYS);
  const messageEntry = findEntry(record, MESSAGE_KEYS);
  const serviceEntry = findEntry(record, SERVICE_KEYS);
  const durationEntry = findEntry(record, DURATION_KEYS);
  const timestamp = parseTimestamp(timestampEntry?.[1]);
  const durationMs = durationEntry ? parseLatency(durationEntry[1], durationEntry[0]) : undefined;
  const canonicalKeys = new Set(
    [timestampEntry, levelEntry, messageEntry, serviceEntry, durationEntry]
      .filter((entry): entry is [string, unknown] => entry !== undefined)
      .map(([key]) => key.split('.')[0]?.toLowerCase()),
  );
  const attributes = Object.fromEntries(Object.entries(record).filter(([key]) => !canonicalKeys.has(key.toLowerCase())));
  const result: ParsedEntry = {
    level: normalizeLevel(levelEntry?.[1]),
    // Do not stringify a whole structured record as a message: doing so would
    // duplicate sensitive fields outside the field-aware redaction path.
    message: safeString(messageEntry?.[1], '(no message)'),
    service: safeString(serviceEntry?.[1], 'unknown'),
    attributes,
    format,
  };
  if (timestamp) result.timestamp = timestamp;
  if (durationMs !== undefined) result.durationMs = durationMs;
  return result;
}

export function parseLogfmt(line: string): Record<string, unknown> | undefined {
  const record: Record<string, unknown> = {};
  const expression = /(?:^|\s)([A-Za-z_@][\w.@-]*)=(?:"((?:\\.|[^"\\])*)"|'([^']*)'|([^\s"'][^\s]*))/g;
  let match: RegExpExecArray | null;
  let fields = 0;
  let cursor = 0;
  while ((match = expression.exec(line)) !== null) {
    if (line.slice(cursor, match.index).trim() !== '') return undefined;
    const key = match[1];
    if (!key) continue;
    const raw = match[2] ?? match[3] ?? match[4] ?? '';
    const value = match[2] !== undefined ? raw.replace(/\\(["\\nrt])/g, (_all, escaped: string) => {
      if (escaped === 'n') return '\n';
      if (escaped === 'r') return '\r';
      if (escaped === 't') return '\t';
      return escaped;
    }) : raw;
    record[key] = value;
    fields += 1;
    cursor = expression.lastIndex;
  }
  if (line.slice(cursor).trim() !== '') return undefined;
  const hasSemanticField = findEntry(record, [...TIMESTAMP_KEYS, ...LEVEL_KEYS, ...MESSAGE_KEYS, ...SERVICE_KEYS]) !== undefined;
  const startsAsLogfmt = /^[A-Za-z_@][\w.@-]*=/.test(line.trim());
  return fields >= 2 && (hasSemanticField || startsAsLogfmt) ? record : undefined;
}

function parsePlain(line: string): ParsedEntry {
  let remainder = line.trim();
  let timestamp: Date | undefined;
  const timestampPatterns = [
    /^\[?(\d{4}-\d{2}-\d{2}[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)\]?\s*/,
    /^\[?((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\]?\s*/i,
    /^\[?(\d{10}(?:\.\d+)?|\d{13})\]?\s*/,
  ];
  for (const pattern of timestampPatterns) {
    const match = pattern.exec(remainder);
    if (!match?.[1]) continue;
    timestamp = parseTimestamp(match[1]);
    remainder = remainder.slice(match[0].length);
    break;
  }

  const levelMatch = /^(?:\[|<)?(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|FATAL|CRITICAL|CRIT)(?:\]|>)?(?![A-Za-z])[:\s-]*/i.exec(remainder)
    ?? /\b(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|FATAL|CRITICAL|CRIT)\b/i.exec(remainder);
  const level = normalizeLevel(levelMatch?.[1]);
  if (levelMatch?.index === 0) remainder = remainder.slice(levelMatch[0].length);

  let service = 'unknown';
  const bracketService = /^\[([\w./-]{1,80})\]\s*/.exec(remainder);
  const namedService = /^(?:service|app|component)=([\w./-]{1,80})\s*/i.exec(remainder);
  const serviceMatch = namedService ?? bracketService;
  if (serviceMatch?.[1]) {
    service = serviceMatch[1];
    remainder = remainder.slice(serviceMatch[0].length);
  }
  remainder = remainder.replace(/^[-:|]\s*/, '').trim();

  const durationMatch = /\b((?:duration|latency|elapsed|response_time)(?:_(?:ms|s))?)[=:]\s*(\d+(?:\.\d+)?\s*(?:ns|us|µs|μs|ms|s)?)\b/i.exec(line);
  const durationMs = durationMatch?.[2] ? parseLatency(durationMatch[2], durationMatch[1] ?? '') : undefined;
  const result: ParsedEntry = {
    level,
    message: remainder || line.trim(),
    service,
    attributes: {},
    format: 'plain',
  };
  if (timestamp) result.timestamp = timestamp;
  if (durationMs !== undefined) result.durationMs = durationMs;
  return result;
}

export function parseLine(line: string): ParseResult {
  const trimmed = line.trim();
  if (!trimmed) return { malformed: false, reason: 'empty' };
  if (trimmed.startsWith('{') || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return { entry: fromRecord(parsed as Record<string, unknown>, 'ndjson'), format: 'ndjson', malformed: false };
      }
      return { entry: parsePlain(trimmed), format: 'plain', malformed: true, reason: 'JSON value is not an object' };
    } catch {
      return { entry: parsePlain(trimmed), format: 'plain', malformed: true, reason: 'Invalid JSON object' };
    }
  }
  const logfmt = parseLogfmt(trimmed);
  if (logfmt) return { entry: fromRecord(logfmt, 'logfmt'), format: 'logfmt', malformed: false };
  return { entry: parsePlain(trimmed), format: 'plain', malformed: false };
}
