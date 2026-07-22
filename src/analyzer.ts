import type { AnalysisReport, AnalyzeOptions, ParsedEntry, TimelineBucket } from './types.js';
import { parseLine } from './parser.js';
import { Redactor } from './redactor.js';
import { QuantileSketch } from './quantiles.js';
import { TemplateMiner } from './cluster.js';
import { detectAnomalies } from './anomaly.js';
import {
  DEFAULT_MAX_SEQUENCE_EVENTS,
  DEFAULT_SEQUENCE_WINDOW_MS,
  findFailurePrecursors,
  type SequenceEvent,
} from './precursors.js';
import { increment, percent, round, sortedCounts, VERSION } from './util.js';
import { basename, isAbsolute, win32 } from 'node:path';

interface BucketState {
  count: number;
  errors: number;
  latency: QuantileSketch;
}

export interface InputLine {
  text: string;
  truncated?: boolean;
}

function truncateUtf8(value: string, maxBytes: number): { text: string; truncated: boolean } {
  const encoded = Buffer.from(value, 'utf8');
  if (encoded.length <= maxBytes) return { text: value, truncated: false };
  return { text: encoded.subarray(0, maxBytes).toString('utf8'), truncated: true };
}

function sourceLabel(source: string): string {
  if (isAbsolute(source)) return basename(source);
  if (win32.isAbsolute(source)) return win32.basename(source);
  return source;
}

function isError(entry: ParsedEntry): boolean {
  return entry.level === 'error' || entry.level === 'fatal';
}

export async function analyzeLines(lines: AsyncIterable<string | InputLine> | Iterable<string | InputLine>, options: AnalyzeOptions = {}): Promise<AnalysisReport> {
  const startedAt = new Date();
  const startedClock = performance.now();
  const bucketMs = options.bucketMs ?? 60_000;
  if (!Number.isFinite(bucketMs) || bucketMs < 1_000) throw new Error('bucketMs must be at least 1000');
  const maxLineLength = options.maxLineLength ?? 2_000_000;
  if (!Number.isSafeInteger(maxLineLength) || maxLineLength < 1) throw new Error('maxLineLength must be a positive safe integer');
  const precursorsEnabled = options.precursors ?? false;
  const sequenceWindowMs = options.sequenceWindowMs ?? DEFAULT_SEQUENCE_WINDOW_MS;
  const maxSequenceEvents = options.maxSequenceEvents ?? DEFAULT_MAX_SEQUENCE_EVENTS;
  if (precursorsEnabled && (!Number.isSafeInteger(sequenceWindowMs) || sequenceWindowMs < 1)) {
    throw new Error('sequenceWindowMs must be a positive safe integer');
  }
  if (precursorsEnabled && (!Number.isSafeInteger(maxSequenceEvents) || maxSequenceEvents < 1)) {
    throw new Error('maxSequenceEvents must be a positive safe integer');
  }
  const redactor = new Redactor(options.redactionConfig, options.redact ?? true);
  const miner = new TemplateMiner(0.6, options.maxSamplesPerTemplate ?? 3);
  const latency = new QuantileSketch();
  const levels = new Map<string, number>();
  const services = new Map<string, number>();
  const formats = new Map<string, number>();
  const buckets = new Map<number, BucketState>();
  const sequenceEvents: SequenceEvent[] | undefined = precursorsEnabled ? [] : undefined;
  let sequenceEventsSeen = 0;
  let linesRead = 0;
  let events = 0;
  let malformedLines = 0;
  let truncatedLines = 0;
  let errors = 0;
  let warnings = 0;
  let missingTimestamps = 0;
  let firstSeen: Date | undefined;
  let lastSeen: Date | undefined;
  let lastTimestampForFallback: Date | undefined;

  for await (const originalLine of lines) {
    linesRead += 1;
    const supplied = typeof originalLine === 'string'
      ? { text: originalLine, truncated: false }
      : { text: originalLine.text, truncated: originalLine.truncated ?? false };
    const bounded = truncateUtf8(supplied.text, maxLineLength);
    const line = bounded.text;
    if (supplied.truncated || bounded.truncated) truncatedLines += 1;
    const parsed = parseLine(line);
    if (parsed.malformed) malformedLines += 1;
    if (!parsed.entry) continue;
    const entry = redactor.redactEntry(parsed.entry);
    events += 1;
    increment(levels, entry.level);
    increment(services, entry.service);
    increment(formats, entry.format);
    if (isError(entry)) errors += 1;
    if (entry.level === 'warn') warnings += 1;
    if (entry.durationMs !== undefined) latency.add(entry.durationMs);

    if (entry.timestamp) {
      if (!firstSeen || entry.timestamp < firstSeen) firstSeen = entry.timestamp;
      if (!lastSeen || entry.timestamp > lastSeen) lastSeen = entry.timestamp;
      lastTimestampForFallback = entry.timestamp;
    } else {
      missingTimestamps += 1;
    }
    const eventTime = entry.timestamp ?? lastTimestampForFallback ?? startedAt;
    const bucket = Math.floor(eventTime.getTime() / bucketMs) * bucketMs;
    let state = buckets.get(bucket);
    if (!state) {
      state = { count: 0, errors: 0, latency: new QuantileSketch(2_000) };
      buckets.set(bucket, state);
    }
    state.count += 1;
    if (isError(entry)) state.errors += 1;
    if (entry.durationMs !== undefined) state.latency.add(entry.durationMs);
    const cluster = miner.add(entry, bucket);
    if (sequenceEvents && entry.timestamp) {
      sequenceEventsSeen += 1;
      if (sequenceEvents.length < maxSequenceEvents) {
        sequenceEvents.push({
          timestampMs: entry.timestamp.getTime(),
          service: entry.service,
          templateId: cluster.id,
          failure: isError(entry),
        });
      }
    }
  }

  const timeline: TimelineBucket[] = [...buckets.entries()]
    .sort(([a], [b]) => a - b)
    .map(([timestamp, state]) => {
      const item: TimelineBucket = {
        timestamp: new Date(timestamp).toISOString(),
        count: state.count,
        errors: state.errors,
        errorRate: percent(state.errors, state.count),
      };
      const p95 = state.latency.quantile(0.95);
      if (p95 !== undefined) item.latencyP95Ms = round(p95, 3);
      return item;
    });
  const clusters = miner.clusters();
  const precursors = precursorsEnabled
    ? findFailurePrecursors(
      sequenceEvents ?? [],
      new Map(clusters.map((cluster) => [cluster.id, cluster.tokens.join(' ')])),
      sequenceWindowMs,
    )
    : [];
  const anomalies = detectAnomalies(timeline, clusters);
  const anomalousTemplates = new Set(anomalies.flatMap((item) => item.templateId ? [item.templateId] : []));
  const safeSource = redactor.redactString(sourceLabel(options.source ?? 'stdin'));
  const redactionStats = redactor.stats();
  const notes: string[] = [];
  if (missingTimestamps > 0) notes.push(`${missingTimestamps} event(s) had no timestamp and were bucketed with the most recent parsed timestamp (or analysis time when none was available).`);
  if (truncatedLines > 0) notes.push(`${truncatedLines} line(s) exceeded the configured byte limit and were truncated.`);
  if (latency.count > 50_000) notes.push('Latency quantiles use a deterministic 50,000-point reservoir for bounded memory.');
  if (timeline.length < 4) notes.push('Anomaly detection requires an observed bucket plus at least three populated baseline buckets.');
  if (precursorsEnabled) {
    notes.push('Candidate failure precursors are temporal associations, not evidence of causality.');
    if (missingTimestamps > 0) notes.push(`${missingTimestamps} event(s) without timestamps were excluded from candidate precursor analysis.`);
    if (sequenceEventsSeen > (sequenceEvents?.length ?? 0)) {
      notes.push(`Candidate precursor analysis retained the first ${(sequenceEvents?.length ?? 0).toLocaleString('en-US')} of ${sequenceEventsSeen.toLocaleString('en-US')} timestamped events; results may be incomplete.`);
    }
  }

  const summary: AnalysisReport['summary'] = {
    linesRead,
    events,
    malformedLines,
    truncatedLines,
    errors,
    warnings,
    errorRate: percent(errors, events),
    services: services.size,
    templates: clusters.length,
  };
  if (firstSeen) summary.firstSeen = firstSeen.toISOString();
  if (lastSeen) summary.lastSeen = lastSeen.toISOString();
  const latencySummary = latency.summary();
  if (latencySummary) summary.latency = latencySummary;

  const precursorAnalysis = precursorsEnabled ? {
    enabled: true as const,
    sequenceWindowMs,
    maxSequenceEvents,
    eventsSeen: sequenceEventsSeen,
    eventsRetained: sequenceEvents?.length ?? 0,
    truncated: sequenceEventsSeen > (sequenceEvents?.length ?? 0),
  } : undefined;

  return {
    schemaVersion: precursorsEnabled ? '1.1' : '1.0',
    metadata: {
      tool: 'LogLoom',
      version: VERSION,
      generatedAt: new Date().toISOString(),
      source: safeSource,
      bucketMs,
      redactionEnabled: redactor.enabled,
      durationMs: Math.round((performance.now() - startedClock) * 100) / 100,
      ...(precursorAnalysis ? { precursorAnalysis } : {}),
    },
    summary,
    formats: sortedCounts(formats, events),
    levels: sortedCounts(levels, events),
    services: sortedCounts(services, events),
    templates: clusters.map((cluster) => {
      const template = {
        id: cluster.id,
        template: cluster.tokens.join(' '),
        count: cluster.count,
        percent: percent(cluster.count, events),
        errors: cluster.errors,
        levels: sortedCounts(cluster.levels, cluster.count),
        services: sortedCounts(cluster.services, cluster.count),
        samples: cluster.samples,
        anomalous: anomalousTemplates.has(cluster.id),
      };
      return Object.assign(template, cluster.firstSeen ? { firstSeen: cluster.firstSeen.toISOString() } : {}, cluster.lastSeen ? { lastSeen: cluster.lastSeen.toISOString() } : {});
    }),
    timeline,
    anomalies,
    ...(precursorsEnabled ? { precursors } : {}),
    privacy: {
      redactions: redactionStats.total,
      byType: redactionStats.byType,
    },
    notes,
  };
}
