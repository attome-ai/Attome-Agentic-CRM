import type { ViewKind } from '@attome/xrm/core/query/data';
import { ChartDraft, EMPTY_CHART_DRAFT, buildChartMetadata, chartDraftFromMetadata } from './chart-metadata';

/** The kind-specific settings the view editor edits (D-429, U13). Mirrors
 * what `validate_view_kind_metadata` in `attome-api/src/view_admin.rs`
 * requires: kanban → `state_field` (+ optional `wip_limits`),
 * calendar/timeline → `start_field` + `end_field` (+ optional `color_field`),
 * chart → `chart_view_metadata` (see `chart-metadata.ts`). */
export interface ViewKindDraft {
  stateField: string;
  /** `state=limit` pairs, comma separated (`open=5, in_progress=3`). */
  wipLimits:  string;
  startField: string;
  endField:   string;
  colorField: string;
  chart:      ChartDraft;
}

export const EMPTY_VIEW_KIND_DRAFT: ViewKindDraft = {
  stateField: '', wipLimits: '', startField: '', endField: '', colorField: '',
  chart: EMPTY_CHART_DRAFT,
};

/** The editor's kind picker. */
export const EDITABLE_VIEW_KINDS: readonly ViewKind[] = ['list', 'kanban', 'calendar', 'timeline', 'chart'];

export type ViewKindMetadataResult =
  | { ok: true; metadata: Record<string, unknown> }
  | { ok: false; errorKey: string };

function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/** Reads a stored view's metadata back into the editor's draft. */
export function draftFromMetadata(kind: ViewKind, metadata: Record<string, unknown> | null | undefined): ViewKindDraft {
  const meta = metadata ?? {};
  const draft: ViewKindDraft = { ...EMPTY_VIEW_KIND_DRAFT };
  if (kind === 'kanban') {
    draft.stateField = str(meta['state_field']);
    const limits = meta['wip_limits'];
    if (limits && typeof limits === 'object' && !Array.isArray(limits)) {
      draft.wipLimits = Object.entries(limits as Record<string, unknown>)
        .filter(([, limit]) => typeof limit === 'number')
        .map(([state, limit]) => `${state}=${limit as number}`)
        .join(', ');
    }
  } else if (kind === 'calendar' || kind === 'timeline') {
    draft.startField = str(meta['start_field']);
    draft.endField   = str(meta['end_field']);
    draft.colorField = str(meta['color_field']);
  } else if (kind === 'chart') {
    draft.chart = chartDraftFromMetadata(meta);
  }
  return draft;
}

/** Parses `open=5, in_progress=3` into `{ open: 5, in_progress: 3 }`. */
export function parseWipLimits(text: string): Record<string, number> | null {
  const limits: Record<string, number> = {};
  for (const part of text.split(',').map(p => p.trim()).filter(Boolean)) {
    const eq = part.lastIndexOf('=');
    if (eq <= 0) return null;
    const state = part.slice(0, eq).trim();
    const raw = part.slice(eq + 1).trim();
    if (!state || !/^\d+$/.test(raw)) return null;
    limits[state] = Number(raw);
  }
  return limits;
}

/** Builds the `view_metadata` body for a save, or names the missing input.
 * `existing` supplies the chart keys the editor does not edit. */
export function buildViewMetadata(
  kind: ViewKind, draft: ViewKindDraft, existing: Record<string, unknown> = {},
): ViewKindMetadataResult {
  switch (kind) {
    case 'list':
      return { ok: true, metadata: {} };
    case 'chart':
      return buildChartMetadata(draft.chart, existing);
    case 'kanban': {
      const stateField = draft.stateField.trim();
      if (!stateField) return { ok: false, errorKey: 'queryAdmin.viewKind.stateFieldRequired' };
      const metadata: Record<string, unknown> = { state_field: stateField };
      if (draft.wipLimits.trim()) {
        const limits = parseWipLimits(draft.wipLimits);
        if (!limits) return { ok: false, errorKey: 'queryAdmin.viewKind.wipLimitsInvalid' };
        metadata['wip_limits'] = limits;
      }
      return { ok: true, metadata };
    }
    case 'calendar':
    case 'timeline': {
      const startField = draft.startField.trim();
      const endField = draft.endField.trim();
      if (!startField || !endField) return { ok: false, errorKey: 'queryAdmin.viewKind.datesRequired' };
      const metadata: Record<string, unknown> = { start_field: startField, end_field: endField };
      if (draft.colorField.trim()) metadata['color_field'] = draft.colorField.trim();
      return { ok: true, metadata };
    }
  }
}
