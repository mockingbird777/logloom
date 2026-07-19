import type { LogLevel, ParsedEntry } from './types.js';
import { increment, stableId } from './util.js';

const VARIABLE = '<*>';
const NORMALIZERS: Array<[RegExp, string]> = [
  [/^\[REDACTED:[A-Z0-9_-]+\][,;:.]?$/i, '<redacted>'],
  [/^(?:https?|wss?):\/\//i, '<url>'],
  [/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}[,;:.]?$/i, '<uuid>'],
  [/^(?:0x)?[0-9a-f]{10,}[,;:.]?$/i, '<hex>'],
  [/^[+-]?\d+(?:\.\d+)?(?:ms|s|m|h|kb|mb|gb|%)?[,;:.]?$/i, '<num>'],
  [/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?[,;:.]?$/, '<ip>'],
  [/^\/[\w./-]{4,}[,;:.]?$/, '<path>'],
];

export interface ClusterState {
  id: string;
  tokens: string[];
  count: number;
  errors: number;
  levels: Map<string, number>;
  services: Map<string, number>;
  buckets: Map<number, number>;
  firstSeen?: Date;
  lastSeen?: Date;
  samples: string[];
}

function tokenize(message: string): string[] {
  return message.trim().match(/\[[^\]]+\]|"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) ?? ['(empty message)'];
}

function normalizeToken(token: string): string {
  for (const [expression, replacement] of NORMALIZERS) {
    if (expression.test(token)) return replacement;
  }
  if (token.length > 96 && /^[A-Za-z0-9+/_=-]+$/.test(token)) return '<blob>';
  return token;
}

function similarity(template: string[], incoming: string[]): number {
  let comparable = 0;
  let matching = 0;
  for (let index = 0; index < template.length; index += 1) {
    const current = template[index];
    if (current === VARIABLE) continue;
    comparable += 1;
    if (current === incoming[index]) matching += 1;
  }
  return comparable === 0 ? 1 : matching / comparable;
}

function isError(level: LogLevel): boolean {
  return level === 'error' || level === 'fatal';
}

export class TemplateMiner {
  private readonly groups = new Map<number, ClusterState[]>();

  constructor(private readonly threshold = 0.6, private readonly maxSamples = 3) {}

  add(entry: ParsedEntry, bucket: number): ClusterState {
    const incoming = tokenize(entry.message).map(normalizeToken);
    const candidates = this.groups.get(incoming.length) ?? [];
    let best: ClusterState | undefined;
    let bestScore = -1;
    for (const candidate of candidates) {
      const score = similarity(candidate.tokens, incoming);
      if (score > bestScore) {
        best = candidate;
        bestScore = score;
      }
    }
    if (!best || bestScore < this.threshold) {
      best = {
        id: stableId(incoming.join(' '), 'tpl_'),
        tokens: incoming,
        count: 0,
        errors: 0,
        levels: new Map(),
        services: new Map(),
        buckets: new Map(),
        samples: [],
      };
      candidates.push(best);
      this.groups.set(incoming.length, candidates);
    } else {
      best.tokens = best.tokens.map((token, index) => token === incoming[index] ? token : VARIABLE);
    }

    best.count += 1;
    if (isError(entry.level)) best.errors += 1;
    increment(best.levels, entry.level);
    increment(best.services, entry.service);
    best.buckets.set(bucket, (best.buckets.get(bucket) ?? 0) + 1);
    if (entry.timestamp && (!best.firstSeen || entry.timestamp < best.firstSeen)) best.firstSeen = entry.timestamp;
    if (entry.timestamp && (!best.lastSeen || entry.timestamp > best.lastSeen)) best.lastSeen = entry.timestamp;
    if (best.samples.length < this.maxSamples && !best.samples.includes(entry.message)) best.samples.push(entry.message.slice(0, 500));
    return best;
  }

  clusters(): ClusterState[] {
    return [...this.groups.values()].flat().sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
  }
}
