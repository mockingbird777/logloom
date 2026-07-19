export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal' | 'unknown';

export type InputFormat = 'ndjson' | 'logfmt' | 'plain';

export interface ParsedEntry {
  timestamp?: Date;
  level: LogLevel;
  message: string;
  service: string;
  durationMs?: number;
  attributes: Record<string, unknown>;
  format: InputFormat;
}

export interface ParseResult {
  entry?: ParsedEntry;
  format?: InputFormat;
  malformed: boolean;
  reason?: string;
}

export interface RedactionPatternConfig {
  name: string;
  regex: string;
  flags?: string;
  replacement?: string;
}

export interface RedactionConfig {
  enabled?: boolean;
  sensitiveFields?: string[];
  patterns?: RedactionPatternConfig[];
}

export interface AnalyzeOptions {
  source?: string;
  bucketMs?: number;
  redact?: boolean;
  redactionConfig?: RedactionConfig;
  maxLineLength?: number;
  maxSamplesPerTemplate?: number;
}

export interface CountItem {
  name: string;
  count: number;
  percent: number;
}

export interface LatencySummary {
  count: number;
  minMs: number;
  maxMs: number;
  meanMs: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
  approximate: boolean;
}

export interface TimelineBucket {
  timestamp: string;
  count: number;
  errors: number;
  errorRate: number;
  latencyP95Ms?: number;
}

export interface TemplateSummary {
  id: string;
  template: string;
  count: number;
  percent: number;
  errors: number;
  firstSeen?: string;
  lastSeen?: string;
  levels: CountItem[];
  services: CountItem[];
  samples: string[];
  anomalous: boolean;
}

export type AnomalyType = 'error-burst' | 'frequency-spike' | 'latency-spike';
export type AnomalySeverity = 'medium' | 'high' | 'critical';

export interface Anomaly {
  id: string;
  type: AnomalyType;
  severity: AnomalySeverity;
  title: string;
  detail: string;
  timestamp: string;
  observed: number;
  expected: number;
  score: number;
  templateId?: string;
}

export interface AnalysisReport {
  schemaVersion: '1.0';
  metadata: {
    tool: 'LogLoom';
    version: string;
    generatedAt: string;
    source: string;
    bucketMs: number;
    redactionEnabled: boolean;
    durationMs: number;
  };
  summary: {
    linesRead: number;
    events: number;
    malformedLines: number;
    truncatedLines: number;
    errors: number;
    warnings: number;
    errorRate: number;
    services: number;
    templates: number;
    firstSeen?: string;
    lastSeen?: string;
    latency?: LatencySummary;
  };
  formats: CountItem[];
  levels: CountItem[];
  services: CountItem[];
  templates: TemplateSummary[];
  timeline: TimelineBucket[];
  anomalies: Anomaly[];
  privacy: {
    redactions: number;
    byType: CountItem[];
  };
  notes: string[];
}
