import type { AnalysisReport } from '../types.js';

export function renderJsonReport(report: AnalysisReport, pretty = true): string {
  return `${JSON.stringify(report, null, pretty ? 2 : 0)}\n`;
}
