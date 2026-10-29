import { describe, expect, it } from 'vitest';
import {
  EMPTY_VIEW_KIND_DRAFT, buildViewMetadata, draftFromMetadata, parseWipLimits,
} from './view-kind-metadata';

describe('view kind metadata (U13)', () => {
  it('list carries no metadata', () => {
    expect(buildViewMetadata('list', EMPTY_VIEW_KIND_DRAFT, { stale: true })).toEqual({ ok: true, metadata: {} });
  });

  it('chart round-trips its stored metadata through the editor draft', () => {
    const stored = { chart_type: 'bar', x_field: 'stage', y_fields: [] };
    expect(buildViewMetadata('chart', draftFromMetadata('chart', stored), stored)).toEqual({ ok: true, metadata: stored });
  });

  it('chart validates through the chart settings', () => {
    const draft = draftFromMetadata('chart', { x_field: 'Not Valid' });
    expect(buildViewMetadata('chart', draft))
      .toEqual({ ok: false, errorKey: 'queryAdmin.viewKind.chartError.xField' });
  });

  it('kanban requires a state field', () => {
    expect(buildViewMetadata('kanban', EMPTY_VIEW_KIND_DRAFT))
      .toEqual({ ok: false, errorKey: 'queryAdmin.viewKind.stateFieldRequired' });
  });

  it('kanban builds state_field and optional wip_limits', () => {
    expect(buildViewMetadata('kanban', { ...EMPTY_VIEW_KIND_DRAFT, stateField: ' status ', wipLimits: 'open=5, in_progress = 3' }))
      .toEqual({ ok: true, metadata: { state_field: 'status', wip_limits: { open: 5, in_progress: 3 } } });
    expect(buildViewMetadata('kanban', { ...EMPTY_VIEW_KIND_DRAFT, stateField: 'status' }))
      .toEqual({ ok: true, metadata: { state_field: 'status' } });
  });

  it('rejects malformed wip limits', () => {
    expect(parseWipLimits('open=five')).toBeNull();
    expect(parseWipLimits('=3')).toBeNull();
    expect(parseWipLimits('open')).toBeNull();
    expect(parseWipLimits('open=-1')).toBeNull();
    expect(buildViewMetadata('kanban', { ...EMPTY_VIEW_KIND_DRAFT, stateField: 's', wipLimits: 'x' }))
      .toEqual({ ok: false, errorKey: 'queryAdmin.viewKind.wipLimitsInvalid' });
  });

  it('calendar and timeline require start and end fields', () => {
    for (const kind of ['calendar', 'timeline'] as const) {
      expect(buildViewMetadata(kind, { ...EMPTY_VIEW_KIND_DRAFT, startField: 'starts_on' }))
        .toEqual({ ok: false, errorKey: 'queryAdmin.viewKind.datesRequired' });
      expect(buildViewMetadata(kind, { ...EMPTY_VIEW_KIND_DRAFT, startField: 'a', endField: 'b', colorField: 'c' }))
        .toEqual({ ok: true, metadata: { start_field: 'a', end_field: 'b', color_field: 'c' } });
      expect(buildViewMetadata(kind, { ...EMPTY_VIEW_KIND_DRAFT, startField: 'a', endField: 'b' }))
        .toEqual({ ok: true, metadata: { start_field: 'a', end_field: 'b' } });
    }
  });

  it('map requires a location field and keeps its optional fields (B15-T2)', () => {
    expect(buildViewMetadata('map', EMPTY_VIEW_KIND_DRAFT))
      .toEqual({ ok: false, errorKey: 'queryAdmin.viewKind.locationRequired' });
    expect(buildViewMetadata('map', { ...EMPTY_VIEW_KIND_DRAFT, locationField: ' location ', labelField: 'name' }))
      .toEqual({ ok: true, metadata: { location_field: 'location', label_field: 'name' } });
    expect(draftFromMetadata('map', { location_field: 'location', color_field: 'status' }))
      .toEqual({ ...EMPTY_VIEW_KIND_DRAFT, locationField: 'location', colorField: 'status' });
  });

  it('round-trips stored metadata into the draft', () => {
    expect(draftFromMetadata('kanban', { state_field: 'status', wip_limits: { open: 5, done: null } }))
      .toEqual({ ...EMPTY_VIEW_KIND_DRAFT, stateField: 'status', wipLimits: 'open=5' });
    expect(draftFromMetadata('timeline', { start_field: 'a', end_field: 'b', color_field: null }))
      .toEqual({ ...EMPTY_VIEW_KIND_DRAFT, startField: 'a', endField: 'b' });
    expect(draftFromMetadata('list', null)).toEqual(EMPTY_VIEW_KIND_DRAFT);
  });
});
