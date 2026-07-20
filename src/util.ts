import { createHash } from 'node:crypto';
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

export const VERSION = '0.2.0';

export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

export function percent(part: number, total: number): number {
  return total === 0 ? 0 : round((part / total) * 100, 2);
}

export function round(value: number, places = 2): number {
  const factor = 10 ** places;
  if (!Number.isFinite(factor) || Math.abs(value) > Number.MAX_SAFE_INTEGER / factor) return value;
  return Math.round((value + Number.EPSILON) * factor) / factor;
}

export function stableId(input: string, prefix = ''): string {
  return `${prefix}${createHash('sha1').update(input).digest('hex').slice(0, 10)}`;
}

export function increment(map: Map<string, number>, key: string, by = 1): void {
  map.set(key, (map.get(key) ?? 0) + by);
}

export function sortedCounts(map: Map<string, number>, total: number): Array<{ name: string; count: number; percent: number }> {
  return [...map.entries()]
    .map(([name, count]) => ({ name, count, percent: percent(count, total) }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

export function parseDuration(value: string): number {
  const match = /^(\d+(?:\.\d+)?)(ms|s|m|h)?$/i.exec(value.trim());
  if (!match) throw new Error(`Invalid duration: ${value}`);
  const amount = Number(match[1]);
  const unit = (match[2] ?? 'ms').toLowerCase();
  const multiplier = unit === 'h' ? 3_600_000 : unit === 'm' ? 60_000 : unit === 's' ? 1_000 : 1;
  return amount * multiplier;
}

export function formatDuration(ms: number): string {
  if (ms < 1) return `${round(ms, 3)}ms`;
  if (ms < 1_000) return `${round(ms, 1)}ms`;
  if (ms < 60_000) return `${round(ms / 1_000, 1)}s`;
  if (ms < 3_600_000) return `${round(ms / 60_000, 1)}m`;
  return `${round(ms / 3_600_000, 1)}h`;
}

export function escapeJsonForHtml(value: unknown): string {
  return JSON.stringify(value)
    .replace(/&/g, '\\u0026')
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

export async function writeFileAtomic(path: string, contents: string): Promise<void> {
  const absolute = resolve(path);
  await mkdir(dirname(absolute), { recursive: true });
  const temporary = `${absolute}.tmp-${process.pid}-${Date.now()}`;
  try {
    await writeFile(temporary, contents, { encoding: 'utf8', mode: 0o600 });
    await rename(temporary, absolute);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}
