import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { MappingComponent } from './mapping.component';
import { MappingDoc, ModelMapping, ModelMappingService, counts, merges, withAttribute } from './model-mapping';

function fakeMapping(): ModelMapping {
  return {
    users: [],
    roles: [],
    entities: [{
      source: 'Opportunity', source_label: 'Opportunity', action: 'map', target: 'opportunity',
      attributes: [
        { source: 'Id', source_label: 'Id', source_type: 'id', action: 'skip', target: 'id', field_type: 'text',
          type_mismatch: false, lookup_target: null, choices: [] },
        { source: 'Name', source_label: 'Name', source_type: 'string', action: 'map', target: 'name',
          field_type: 'text', type_mismatch: false, lookup_target: null, choices: [] },
        { source: 'Probability', source_label: 'Probability', source_type: 'percent', action: 'map',
          target: 'probability', field_type: 'date', type_mismatch: true, lookup_target: null, choices: [] },
        { source: 'StageName', source_label: 'Stage', source_type: 'picklist', action: 'create', target: 'stage_name',
          field_type: 'choice', type_mismatch: false, lookup_target: null,
          choices: [{ source: 'Won', target: 'won' }, { source: 'Lost', target: null }] },
      ],
    }],
  };
}

const doc = (mapping: ModelMapping, row_version = 1, problems: string[] = []): MappingDoc => ({
  project_id: 'p1', row_version, source_model: { entities: [] }, mapping, problems, updated_at: '2026-10-27T00:00:00Z',
});

describe('model mapping (A24-T3)', () => {
  it('counts actions and marks two fields going into one attribute', () => {
    const m = fakeMapping();
    expect(counts(m)).toEqual({ map: 2, create: 1, skip: 1 });
    const merged = withAttribute(m, 0, 2, { target: 'name' });
    expect([...merges(merged.entities[0])]).toEqual(['name']);
    expect(m.entities[0].attributes[2].target).toBe('probability');
  });

  function setUp(service: Partial<Record<keyof ModelMappingService, unknown>>) {
    TestBed.configureTestingModule({
      imports: [MappingComponent],
      providers: [
        { provide: ModelMappingService, useValue: service },
        {
          provide: LangService,
          useValue: {
            translate: (k: string, p?: Record<string, unknown>) => (p ? `${k} ${JSON.stringify(p)}` : k),
            errorText: () => 'error',
            isRtl: signal(false),
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(MappingComponent);
    fixture.componentRef.setInput('id', 'p1');
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  }

  it('shows the mapping as a table, edits it and saves it on its version', () => {
    const save = vi.fn((_id: string, m: ModelMapping) => of(doc(m, 2)));
    const { cmp, el } = setUp({ get: () => of(doc(fakeMapping(), 1, ['Opportunity.Name: no attribute'])), save });
    expect(el.querySelectorAll('tbody tr').length).toBe(4);
    expect(el.querySelector('[data-testid="mapping-problems"]')?.textContent).toContain('no attribute');
    expect(el.querySelector('.type-mismatch')).not.toBeNull();
    expect(el.querySelector('.choice-summary')?.textContent).toContain('"unmatched":1');

    // Rename a target, skip a field, change a created field's type.
    const target = el.querySelector<HTMLInputElement>('[data-attr-target="Name"]');
    if (target) { target.value = 'title'; target.dispatchEvent(new Event('change')); }
    const action = el.querySelector<HTMLSelectElement>('[data-attr-action="Probability"]');
    if (action) { action.value = 'skip'; action.dispatchEvent(new Event('change')); }
    const type = el.querySelector<HTMLSelectElement>('[data-attr-type="StageName"]');
    if (type) { type.value = 'text'; type.dispatchEvent(new Event('change')); }
    expect(cmp.dirty()).toBe(true);
    cmp.save();
    expect(save).toHaveBeenCalledOnce();
    const [, saved, version] = save.mock.calls[0] as unknown as [string, ModelMapping, number];
    expect(version).toBe(1);
    const attrs = saved.entities[0].attributes;
    expect(attrs[1].target).toBe('title');
    expect(attrs[2].action).toBe('skip');
    expect(attrs[3].field_type).toBe('text');
    expect(cmp.dirty()).toBe(false);
    expect(cmp.doc()?.row_version).toBe(2);
  });

  it('drafts a mapping from a pasted source model when there is none yet', () => {
    const draft = vi.fn(() => of(doc(fakeMapping())));
    const { cmp, fixture, el } = setUp({ get: () => throwError(() => ({ status: 404, kind: 'not_found', message: '' })), draft });
    expect(el.querySelector('[data-testid="mapping-draft"]')).not.toBeNull();
    cmp.sourceText.set('not json');
    cmp.draft();
    expect(cmp.error()).toBe('modelMapping.notJson');
    const model = { entities: [{ name: 'Opportunity', label: 'Opportunity', custom: false, fields: [] }] };
    cmp.sourceText.set(JSON.stringify({ source_model: model }));
    cmp.draft();
    expect(draft).toHaveBeenCalledWith('p1', model);
    fixture.detectChanges();
    expect(el.querySelectorAll('table.mapping-table').length).toBe(1);
  });

  it('reads the source model from a connected system, ready to draft', () => {
    const model = { entities: [{ name: 'deals', label: 'deals', custom: false, fields: [] }] };
    const describe = vi.fn(() => of({ kind: 'hubspot', source_model: model }));
    const { cmp } = setUp({ get: () => throwError(() => ({ status: 404, kind: 'not_found', message: '' })), describe });
    cmp.system.set('hubspot-prod');
    cmp.describe();
    expect(describe).toHaveBeenCalledWith('p1', 'hubspot-prod');
    expect(JSON.parse(cmp.sourceText())).toEqual(model);
    expect(cmp.busy()).toBe(false);
  });

  it('says so when someone else saved first', () => {
    const save = vi.fn(() => throwError(() => ({ status: 409, kind: 'version_conflict', message: '' })));
    const { cmp } = setUp({ get: () => of(doc(fakeMapping())), save });
    cmp.setTarget(0, 1, { target: { value: 'title' } } as unknown as Event);
    cmp.save();
    expect(cmp.error()).toBe('modelMapping.conflict');
    expect(cmp.dirty()).toBe(true);
  });
});
