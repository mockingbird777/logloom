import type { ParsedEntry, RedactionConfig, RedactionPatternConfig } from './types.js';
import { increment, sortedCounts } from './util.js';

interface CompiledPattern {
  name: string;
  regex: RegExp;
  replacement: string;
}

const DEFAULT_FIELDS = [
  'password', 'passwd', 'pwd', 'secret', 'token', 'access_token', 'refresh_token', 'id_token',
  'api_key', 'apikey', 'x-api-key', 'authorization', 'proxy-authorization', 'auth', 'cookie', 'set-cookie',
  'private_key', 'client_secret', 'aws_secret_access_key', 'connection_string',
];

// IPv6 building blocks. The alternation is exhaustive rather than a single
// loose expression so that colon-separated look-alikes (timestamps, MAC
// addresses, C++ `::` scope operators) never match: every compressed form
// requires a literal `::`, and the full form requires all eight groups.
const H16 = '[0-9A-Fa-f]{1,4}';
const IPV4 = '(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}';
// An embedded IPv4 address occupies two IPv6 positions, so a compressed mixed
// form may contain at most five explicit h16 groups. Couple the counts on both
// sides of `::` instead of allowing each side to independently reach its max.
const COMPRESSED_MIXED_IPV6 = Array.from({ length: 5 }, (_value, index) => {
  const before = index + 1;
  const after = 5 - before;
  return `(?:${H16}:){${before}}:(?:${H16}:){0,${after}}${IPV4}`;
}).join('|');
const IPV6 = [
  `(?:${H16}:){6}${IPV4}`, // x:x:x:x:x:x:d.d.d.d
  `::(?:${H16}:){0,5}${IPV4}`, // ::ffff:d.d.d.d and other compressed-mixed forms
  COMPRESSED_MIXED_IPV6, // x::x:d.d.d.d, with at most five total h16 groups
  `(?:${H16}:){7}${H16}`, // full form
  `(?:${H16}:){1,7}:`, // x:: through x:x:x:x:x:x:x::
  `(?:${H16}:){1,6}:${H16}`, // x::x
  `(?:${H16}:){1,5}(?::${H16}){1,2}`,
  `(?:${H16}:){1,4}(?::${H16}){1,3}`,
  `(?:${H16}:){1,3}(?::${H16}){1,4}`,
  `(?:${H16}:){1,2}(?::${H16}){1,5}`,
  `${H16}:(?::${H16}){1,6}`, // x::x:x:x:x:x:x
  `:(?::${H16}){1,7}`, // ::1 and friends (bare `::` is deliberately excluded)
].join('|');

const DEFAULT_PATTERNS: RedactionPatternConfig[] = [
  { name: 'JWT', regex: '\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{4,}\\b' },
  { name: 'BEARER', regex: '\\bBearer\\s+[A-Za-z0-9._~+/-]{8,}={0,2}', flags: 'gi' },
  { name: 'AWS_KEY', regex: '\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b' },
  { name: 'GITHUB_TOKEN', regex: '\\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\\b' },
  { name: 'PRIVATE_KEY', regex: '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\\s\\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', flags: 'g' },
  { name: 'SECRET', regex: "\\b((?:api[_-]?key|token|secret|password|passwd|pwd|client[_-]?secret|aws[_-]?secret[_-]?access[_-]?key)[\"']?\\s*[=:]\\s*)[\"']?([^\\s,\"']{4,})", flags: 'gi', replacement: '$1[REDACTED:SECRET]' },
  { name: 'EMAIL', regex: '\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b', flags: 'gi' },
  // IPv6 must run before IPv4 so IPv4-mapped forms (::ffff:192.0.2.1) are
  // redacted whole instead of leaving `::ffff:` behind. Both count as 'IP'.
  { name: 'IP', regex: `(?<![A-Za-z0-9:.])(?:${IPV6})(?![A-Za-z0-9:]|\\.\\d)`, flags: 'g' },
  // Do not partially redact an IPv4 tail after two h16 groups or a compressed
  // h16 chain. Valid mixed forms were handled above; these contexts are an
  // invalid/overlong IPv6-like token. A normal `ip:192.0.2.1` still redacts.
  { name: 'IP', regex: `(?<![\\d.])(?<!${H16}:${H16}:)(?<!${H16}::)(?<!::${H16}:)${IPV4}(?![\\d.])`, flags: 'g' },
  { name: 'ABSOLUTE_PATH', regex: '(?<![A-Za-z0-9])(?:[A-Za-z]:\\\\(?:Users|Windows|Program Files|ProgramData|Temp)\\\\[^\\s\"\'<>]+|/(?:Users|home|root|private|tmp|var|etc|opt|usr)/[^\\s\"\'<>]+)', flags: 'gi' },
];

export interface RedactionStats {
  total: number;
  byType: ReturnType<typeof sortedCounts>;
}

export class Redactor {
  readonly enabled: boolean;
  private readonly fields: Set<string>;
  private readonly patterns: CompiledPattern[];
  private readonly counts = new Map<string, number>();

  constructor(config: RedactionConfig = {}, enabled = true) {
    this.enabled = config.enabled ?? enabled;
    this.fields = new Set([...DEFAULT_FIELDS, ...(config.sensitiveFields ?? [])].flatMap((field) => this.fieldForms(field)));
    this.patterns = [...DEFAULT_PATTERNS, ...(config.patterns ?? [])].map((pattern) => this.compile(pattern));
  }

  redactEntry(entry: ParsedEntry): ParsedEntry {
    if (!this.enabled) return entry;
    const result: ParsedEntry = {
      ...entry,
      message: this.redactString(entry.message),
      service: this.redactString(entry.service),
      attributes: this.redactValue(entry.attributes) as Record<string, unknown>,
    };
    return result;
  }

  redactString(input: string): string {
    if (!this.enabled || input.length === 0) return input;
    let output = input;
    for (const pattern of this.patterns) {
      pattern.regex.lastIndex = 0;
      let hits = 0;
      output = output.replace(pattern.regex, (...args: unknown[]) => {
        hits += 1;
        if (pattern.replacement.includes('$')) {
          return pattern.replacement.replace(/\$(\d+)/g, (_token, index: string) => String(args[Number(index)] ?? ''));
        }
        return pattern.replacement;
      });
      if (hits > 0) increment(this.counts, pattern.name, hits);
    }
    return output;
  }

  stats(): RedactionStats {
    const total = [...this.counts.values()].reduce((sum, count) => sum + count, 0);
    return { total, byType: sortedCounts(this.counts, total) };
  }

  private redactValue(value: unknown, key?: string, seen = new WeakSet<object>()): unknown {
    if (key && this.fieldForms(key).some((form) => this.fields.has(form))) {
      increment(this.counts, 'FIELD');
      return '[REDACTED:FIELD]';
    }
    if (typeof value === 'string') return this.redactString(value);
    if (!value || typeof value !== 'object') return value;
    if (seen.has(value)) return '[CIRCULAR]';
    seen.add(value);
    if (Array.isArray(value)) return value.map((item) => this.redactValue(item, undefined, seen));
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([childKey, childValue]) => [
      childKey,
      this.redactValue(childValue, childKey, seen),
    ]));
  }

  private fieldForms(field: string): string[] {
    const lower = field.toLowerCase();
    const leaf = lower.split(/[.[\]]/).filter(Boolean).at(-1) ?? lower;
    return [...new Set([lower, leaf, lower.replace(/[^a-z0-9]/g, ''), leaf.replace(/[^a-z0-9]/g, '')])];
  }

  private compile(pattern: RedactionPatternConfig): CompiledPattern {
    if (!/^[A-Z0-9_-]{1,40}$/i.test(pattern.name)) throw new Error(`Invalid redaction pattern name: ${pattern.name}`);
    const rawFlags = pattern.flags ?? 'g';
    const flags = rawFlags.includes('g') ? rawFlags : `${rawFlags}g`;
    return {
      name: pattern.name.toUpperCase(),
      regex: new RegExp(pattern.regex, flags),
      replacement: pattern.replacement ?? `[REDACTED:${pattern.name.toUpperCase()}]`,
    };
  }
}
