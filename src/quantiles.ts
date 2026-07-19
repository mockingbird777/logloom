import type { LatencySummary } from './types.js';
import { round } from './util.js';

export class QuantileSketch {
  private readonly samples: number[] = [];
  private seen = 0;
  private mean = 0;
  private minimum = Number.POSITIVE_INFINITY;
  private maximum = Number.NEGATIVE_INFINITY;
  private state = 0x9e3779b9;

  constructor(private readonly capacity = 50_000) {}

  add(value: number): void {
    if (!Number.isFinite(value) || value < 0) return;
    this.seen += 1;
    this.mean += (value - this.mean) / this.seen;
    this.minimum = Math.min(this.minimum, value);
    this.maximum = Math.max(this.maximum, value);
    if (this.samples.length < this.capacity) {
      this.samples.push(value);
      return;
    }
    this.state = (Math.imul(this.state, 1_664_525) + 1_013_904_223) >>> 0;
    const index = Math.floor((this.state / 0x1_0000_0000) * this.seen);
    if (index < this.capacity) this.samples[index] = value;
  }

  get count(): number {
    return this.seen;
  }

  quantile(q: number): number | undefined {
    if (this.samples.length === 0) return undefined;
    const sorted = [...this.samples].sort((a, b) => a - b);
    const position = Math.max(0, Math.min(sorted.length - 1, (sorted.length - 1) * q));
    const lower = Math.floor(position);
    const upper = Math.ceil(position);
    const lowerValue = sorted[lower] ?? 0;
    const upperValue = sorted[upper] ?? lowerValue;
    return lowerValue + (upperValue - lowerValue) * (position - lower);
  }

  summary(): LatencySummary | undefined {
    if (this.seen === 0) return undefined;
    return {
      count: this.seen,
      minMs: round(this.minimum, 3),
      maxMs: round(this.maximum, 3),
      meanMs: round(this.mean, 3),
      p50Ms: round(this.quantile(0.5) ?? 0, 3),
      p95Ms: round(this.quantile(0.95) ?? 0, 3),
      p99Ms: round(this.quantile(0.99) ?? 0, 3),
      approximate: this.seen > this.capacity,
    };
  }
}
