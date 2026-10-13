import { ComponentFixture, TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { describe, expect, it } from 'vitest';
import {
  ChartFieldOption, WidgetFieldChange, WidgetInspectorComponent,
} from './widget-inspector.component';

/**
 * Dashboard 10/10 Phase 5.A — the typed filters/bindings builder added to
 * the structured `config.data` panel (source/measures/group/series/
 * presentation already had a typed form; this closes the remaining gap
 * instead of raw JSON editing). Every assertion reads the last
 * `fieldChange` emission's `config` value back as `DataDefinition` JSON,
 * the same contract `attome_core::data_definition::DataDefinition`
 * validates server-side.
 */

const FIELD_OPTIONS: ChartFieldOption[] = [
  { name: 'amount', label: 'Amount', is_date: false, is_numeric: true },
  { name: 'status', label: 'Status', is_date: false },
  { name: 'created_on', label: 'Created On', is_date: true },
];

function widget(config: Record<string, unknown> = {}): EntityRecord {
  return {
    id: 'widget-1',
    entity_id: 'dashboard_widget',
    data: { widget_type: 'bar_chart', config: JSON.stringify(config) },
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    row_version: 0,
  };
}

/** Mirrors what `PageEditorComponent.onWidgetField` really does: applies
 * each `fieldChange` emission back onto the widget and re-sets the
 * `[widget]` input, so the panel's own `config`/`definition` computeds see
 * the latest state on the next call — exactly like the real parent/child
 * round trip, not a one-shot snapshot. Without this, two sequential
 * mutating calls (e.g. `addFilter()` then `onFilterOpChange()`) would both
 * read the same stale, empty `filters` array. */
function setup(config: Record<string, unknown> = { data: { source: 'opportunity', measures: [{ aggregation: 'count' }] } }) {
  TestBed.configureTestingModule({
    imports: [WidgetInspectorComponent],
    providers: [{ provide: LangService, useValue: { translate: (key: string) => key } }],
  });

  const fixture: ComponentFixture<WidgetInspectorComponent> = TestBed.createComponent(WidgetInspectorComponent);
  let current = widget(config);
  fixture.componentRef.setInput('widget', current);
  fixture.componentRef.setInput('fieldOptions', FIELD_OPTIONS);
  fixture.componentRef.setInput('declaredParameters', ['region', 'owner']);
  const component = fixture.componentInstance;

  const emissions: WidgetFieldChange[] = [];
  component.fieldChange.subscribe(e => {
    emissions.push(e);
    current = { ...current, data: { ...current.data, [e.key]: e.value } };
    fixture.componentRef.setInput('widget', current);
  });

  return { component, emissions };
}

/** Parses the last `config` emission's `data` object — every mutating
 * method under test emits `{ key: 'config', value: JSON.stringify({data}) }`. */
function lastDefinition(emissions: WidgetFieldChange[]): Record<string, unknown> {
  const last = emissions.at(-1)!;
  expect(last.key).toBe('config');
  return (JSON.parse(last.value as string) as { data: Record<string, unknown> }).data;
}

describe('WidgetInspectorComponent — filters (Dashboard 10/10 Phase 5.A)', () => {
  it('addFilter appends a default eq filter on the first available field', () => {
    const { component, emissions } = setup();

    component.addFilter();

    const filters = lastDefinition(emissions)['filters'] as Record<string, unknown>[];
    expect(filters).toEqual([{ field: 'amount', op: 'eq', value: '' }]);
  });

  it('removeFilter drops the row at that index', () => {
    const { component } = setup();

    component.addFilter();
    component.addFilter();
    component.removeFilter(0);

    expect(component.filters().length).toBe(1);
  });

  it('switching op to is_null clears the value; switching to a list op resets it to an array', () => {
    const { component, emissions } = setup();
    component.addFilter();

    component.onFilterOpChange(0, 'is_null');
    expect((lastDefinition(emissions)['filters'] as Record<string, unknown>[])[0]['value']).toBeUndefined();

    component.onFilterOpChange(0, 'contains_any');
    expect((lastDefinition(emissions)['filters'] as Record<string, unknown>[])[0]['value']).toEqual([]);
  });

  it('a comma-separated value is split into an array for list ops, kept scalar otherwise', () => {
    const { component, emissions } = setup();
    component.addFilter();
    component.onFilterOpChange(0, 'in');

    component.onFilterValueChange(0, 'a, b , c');
    expect((lastDefinition(emissions)['filters'] as Record<string, unknown>[])[0]['value']).toEqual(['a', 'b', 'c']);

    component.onFilterOpChange(0, 'eq');
    component.onFilterValueChange(0, 'solo');
    expect((lastDefinition(emissions)['filters'] as Record<string, unknown>[])[0]['value']).toBe('solo');
  });

  it('isListFilterOp is true only for contains_any/contains_all/in', () => {
    const { component } = setup();
    expect(component.isListFilterOp('in')).toBe(true);
    expect(component.isListFilterOp('contains_any')).toBe(true);
    expect(component.isListFilterOp('contains_all')).toBe(true);
    expect(component.isListFilterOp('eq')).toBe(false);
    expect(component.isListFilterOp('is_null')).toBe(false);
  });
});

describe('WidgetInspectorComponent — bindings (Dashboard 10/10 Phase 5.A)', () => {
  it('addBinding defaults to a parameter source with the first declared parameter name', () => {
    const { component, emissions } = setup();

    component.addBinding();

    const bindings = lastDefinition(emissions)['bindings'] as Record<string, unknown>[];
    expect(bindings).toEqual([{ source: 'parameter', name: 'region', field: 'amount', op: 'eq' }]);
  });

  it('changing source to builtin repopulates name from BUILTIN_NAMES, not the stale parameter name', () => {
    const { component, emissions } = setup();
    component.addBinding();

    component.onBindingSourceChange(0, 'builtin');

    const binding = (lastDefinition(emissions)['bindings'] as Record<string, unknown>[])[0];
    expect(binding['source']).toBe('builtin');
    expect(binding['name']).toBe('@current_user');
  });

  it('changing source to variable clears name to empty (free text, no closed list)', () => {
    const { component, emissions } = setup();
    component.addBinding();

    component.onBindingSourceChange(0, 'variable');

    const binding = (lastDefinition(emissions)['bindings'] as Record<string, unknown>[])[0];
    expect(binding['source']).toBe('variable');
    expect(binding['name']).toBe('');
  });

  it('bindingNameOptions returns the declared parameters, the builtin list, or nothing for variable', () => {
    const { component } = setup();
    expect(component.bindingNameOptions('parameter')).toEqual(['region', 'owner']);
    expect(component.bindingNameOptions('builtin')).toContain('@current_user');
    expect(component.bindingNameOptions('variable')).toEqual([]);
  });

  it('removeBinding drops the row at that index', () => {
    const { component } = setup();
    component.addBinding();
    component.addBinding();

    component.removeBinding(0);

    expect(component.bindings().length).toBe(1);
  });
});
