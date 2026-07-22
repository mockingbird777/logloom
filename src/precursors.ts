import type { FailurePrecursor } from './types.js';
import { percent, round } from './util.js';

export const DEFAULT_SEQUENCE_WINDOW_MS = 5 * 60_000;
export const DEFAULT_MAX_SEQUENCE_EVENTS = 100_000;
export const MIN_PRECURSOR_SUPPORT = 2;
export const MIN_PRECURSOR_LIFT = 1.25;

export interface SequenceEvent {
  timestampMs: number;
  service: string;
  templateId: string;
  failure: boolean;
}

interface AssociationState {
  support: number;
  gaps: number[];
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function median(values: number[]): number {
  values.sort((left, right) => left - right);
  const middle = Math.floor(values.length / 2);
  const upper = values[middle] ?? 0;
  if (values.length % 2 === 1) return upper;
  return ((values[middle - 1] ?? upper) + upper) / 2;
}

/**
 * Finds temporal associations, not causal relationships. Each non-failure
 * event is associated with at most one failure: the nearest subsequent one in
 * the same service and inside the configured window.
 */
export function findFailurePrecursors(
  events: SequenceEvent[],
  templateText: ReadonlyMap<string, string>,
  windowMs: number,
): FailurePrecursor[] {
  const byService = new Map<string, SequenceEvent[]>();
  for (const event of [...events].sort((left, right) => left.timestampMs - right.timestampMs)) {
    const serviceEvents = byService.get(event.service) ?? [];
    serviceEvents.push(event);
    byService.set(event.service, serviceEvents);
  }

  const candidates: FailurePrecursor[] = [];
  for (const [service, serviceEvents] of byService) {
    let nonFailureEvents = 0;
    let nextFailure: SequenceEvent | undefined;
    const sourceOccurrences = new Map<string, number>();
    const baselineSupport = new Map<string, number>();
    const associations = new Map<string, Map<string, AssociationState>>();

    for (let index = serviceEvents.length - 1; index >= 0; index -= 1) {
      const event = serviceEvents[index];
      if (!event) continue;
      if (event.failure) {
        nextFailure = event;
        continue;
      }

      nonFailureEvents += 1;
      sourceOccurrences.set(event.templateId, (sourceOccurrences.get(event.templateId) ?? 0) + 1);
      if (!nextFailure) continue;
      const gap = nextFailure.timestampMs - event.timestampMs;
      if (gap < 0 || gap > windowMs) continue;

      baselineSupport.set(nextFailure.templateId, (baselineSupport.get(nextFailure.templateId) ?? 0) + 1);
      const byFailure = associations.get(event.templateId) ?? new Map<string, AssociationState>();
      const association = byFailure.get(nextFailure.templateId) ?? { support: 0, gaps: [] };
      association.support += 1;
      association.gaps.push(gap);
      byFailure.set(nextFailure.templateId, association);
      associations.set(event.templateId, byFailure);
    }

    for (const [sourceTemplateId, byFailure] of associations) {
      const occurrences = sourceOccurrences.get(sourceTemplateId) ?? 0;
      if (occurrences === 0 || nonFailureEvents === 0) continue;
      for (const [failureTemplateId, association] of byFailure) {
        const baselineProbability = (baselineSupport.get(failureTemplateId) ?? 0) / nonFailureEvents;
        if (baselineProbability === 0) continue;
        const lift = (association.support / occurrences) / baselineProbability;
        if (association.support < MIN_PRECURSOR_SUPPORT || lift < MIN_PRECURSOR_LIFT) continue;
        candidates.push({
          service,
          sourceTemplateId,
          sourceTemplate: templateText.get(sourceTemplateId) ?? sourceTemplateId,
          failureTemplateId,
          failureTemplate: templateText.get(failureTemplateId) ?? failureTemplateId,
          occurrences,
          support: association.support,
          supportPercent: percent(association.support, occurrences),
          lift: round(lift, 3),
          medianGapMs: round(median(association.gaps), 3),
        });
      }
    }
  }

  return candidates.sort((left, right) =>
    right.support - left.support
    || right.lift - left.lift
    || right.supportPercent - left.supportPercent
    || compareText(left.service, right.service)
    || compareText(left.sourceTemplateId, right.sourceTemplateId)
    || compareText(left.failureTemplateId, right.failureTemplateId));
}
