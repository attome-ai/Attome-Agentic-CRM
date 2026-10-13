import type { LangService } from '@attome/base';
import {
  ACTION_OUTCOMES, DRIFT_STATUSES, FLEET_ENVIRONMENTS, FLEET_ITEM_KINDS, FLEET_ITEM_STATUSES,
  FLEET_REPORT_STATUSES, FLEET_RINGS, ROLLOUT_STATUSES, TARGET_STATUSES, WAVE_STATES,
} from './fleet.types';

/**
 * The fixed server values the console shows as words. A value outside the
 * list (a newer server) is shown as the server sent it rather than as a
 * missing catalog key.
 */
export const FLEET_LABELS = {
  environment:  { prefix: 'fleet.environment',  known: FLEET_ENVIRONMENTS },
  ring:         { prefix: 'fleet.ring',         known: FLEET_RINGS },
  drift:        { prefix: 'fleet.drift.status', known: DRIFT_STATUSES },
  driftField:   { prefix: 'fleet.drift.field',  known: ['schema_version', 'application_version', 'image_digest', 'config_hash'] },
  rollout:      { prefix: 'fleet.rolloutStatus', known: ROLLOUT_STATUSES },
  wave:         { prefix: 'fleet.waveState',    known: WAVE_STATES },
  target:       { prefix: 'fleet.targetStatus', known: TARGET_STATUSES },
  outcome:      { prefix: 'fleet.outcome',      known: ACTION_OUTCOMES },
  reportStatus: { prefix: 'fleet.reportStatus', known: FLEET_REPORT_STATUSES },
  itemStatus:   { prefix: 'fleet.itemStatus',   known: FLEET_ITEM_STATUSES },
  itemKind:     { prefix: 'fleet.itemKind',     known: FLEET_ITEM_KINDS },
  phase:        { prefix: 'fleet.planPhase',    known: ['expand', 'contract'] },
} as const;

export type FleetLabelSet = keyof typeof FLEET_LABELS;

/** The catalog text of a fixed server value, or the value itself when it is not one we know. */
export function fleetLabel(
  lang: Pick<LangService, 'translate'>,
  set: FleetLabelSet,
  value: string | null | undefined,
): string {
  if (!value) return '';
  const { prefix, known } = FLEET_LABELS[set];
  return (known as readonly string[]).includes(value) ? lang.translate(`${prefix}.${value}`) : value;
}

/** A conflict value as short text (JSON for anything that is not a plain scalar). */
export function valueText(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
