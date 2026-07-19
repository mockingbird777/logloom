import type { Anomaly, AnomalySeverity, TimelineBucket } from './types.js';
import type { ClusterState } from './cluster.js';
import { round, stableId } from './util.js';

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  const current = sorted[middle] ?? 0;
  return sorted.length % 2 === 0 ? ((sorted[middle - 1] ?? current) + current) / 2 : current;
}

function robustScore(value: number, baseline: number[]): { expected: number; score: number } {
  if (baseline.length === 0) return { expected: 0, score: 0 };
  const expected = median(baseline);
  const mad = median(baseline.map((item) => Math.abs(item - expected)));
  if (mad > 0) return { expected, score: (value - expected) / (1.4826 * mad) };
  const poissonScale = Math.sqrt(Math.max(expected, 1));
  return { expected, score: (value - expected) / poissonScale };
}

function severity(score: number, ratio: number): AnomalySeverity {
  if (score >= 10 || ratio >= 10) return 'critical';
  if (score >= 6 || ratio >= 5) return 'high';
  return 'medium';
}

function anomaly(input: Omit<Anomaly, 'id'>): Anomaly {
  return { ...input, id: stableId(`${input.type}:${input.timestamp}:${input.templateId ?? ''}`, 'ano_') };
}

export function detectAnomalies(timeline: TimelineBucket[], clusters: ClusterState[]): Anomaly[] {
  if (timeline.length < 2) return [];
  const anomalies: Anomaly[] = [];
  const errorCounts = timeline.map((bucket) => bucket.errors);
  const latencies = timeline.map((bucket) => bucket.latencyP95Ms).filter((value): value is number => value !== undefined);

  timeline.forEach((bucket, index) => {
    const baselineErrors = errorCounts.filter((_value, candidate) => candidate !== index);
    if (baselineErrors.length < 3) return;
    const error = robustScore(bucket.errors, baselineErrors);
    const errorRatio = bucket.errors / Math.max(error.expected, 0.5);
    if (bucket.errors >= 3 && error.score >= 3 && errorRatio >= 2) {
      anomalies.push(anomaly({
        type: 'error-burst',
        severity: severity(error.score, errorRatio),
        title: 'Error burst detected',
        detail: `${bucket.errors} errors landed in this bucket; the robust baseline is ${round(error.expected, 1)}.`,
        timestamp: bucket.timestamp,
        observed: bucket.errors,
        expected: round(error.expected, 3),
        score: round(error.score, 2),
      }));
    }

    if (bucket.latencyP95Ms !== undefined && latencies.length >= 4) {
      const baseline = timeline
        .filter((_item, candidate) => candidate !== index)
        .map((item) => item.latencyP95Ms)
        .filter((value): value is number => value !== undefined);
      if (baseline.length < 3) return;
      const latency = robustScore(bucket.latencyP95Ms, baseline);
      const latencyRatio = bucket.latencyP95Ms / Math.max(latency.expected, 0.001);
      if (latency.score >= 3.5 && latencyRatio >= 1.8) {
        anomalies.push(anomaly({
          type: 'latency-spike',
          severity: severity(latency.score, latencyRatio),
          title: 'Latency regression detected',
          detail: `Bucket p95 reached ${round(bucket.latencyP95Ms, 2)} ms versus a ${round(latency.expected, 2)} ms baseline.`,
          timestamp: bucket.timestamp,
          observed: round(bucket.latencyP95Ms, 3),
          expected: round(latency.expected, 3),
          score: round(latency.score, 2),
        }));
      }
    }
  });

  const bucketEpochs = timeline.map((bucket) => Date.parse(bucket.timestamp));
  for (const cluster of clusters) {
    if (cluster.count < 5 || cluster.buckets.size < 2) continue;
    const values = bucketEpochs.map((epoch) => cluster.buckets.get(epoch) ?? 0);
    values.forEach((value, index) => {
      if (value < 5) return;
      const baseline = values.filter((_item, candidate) => candidate !== index);
      if (baseline.length < 3) return;
      const result = robustScore(value, baseline);
      const ratio = value / Math.max(result.expected, 0.5);
      if (result.score < 4 || ratio < 3) return;
      const timestamp = timeline[index]?.timestamp;
      if (!timestamp) return;
      anomalies.push(anomaly({
        type: 'frequency-spike',
        severity: severity(result.score, ratio),
        title: 'Template frequency spike',
        detail: `“${cluster.tokens.join(' ').slice(0, 140)}” appeared ${value} times in one bucket.`,
        timestamp,
        observed: value,
        expected: round(result.expected, 3),
        score: round(result.score, 2),
        templateId: cluster.id,
      }));
    });
  }

  const rank: Record<AnomalySeverity, number> = { critical: 3, high: 2, medium: 1 };
  return anomalies
    .sort((a, b) => rank[b.severity] - rank[a.severity] || b.score - a.score || a.timestamp.localeCompare(b.timestamp))
    .slice(0, 100);
}
