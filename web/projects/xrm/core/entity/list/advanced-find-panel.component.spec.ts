import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { FieldSchema } from '@attome/xrm';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EntityService } from '../services/entity.service';
import { AdvancedFindPanelComponent } from './advanced-find-panel.component';
import type { QueryFilter } from './column-filters';

const field = (name: string, field_type: FieldSchema['field_type'], options: FieldSchema['options'] = null): FieldSchema => ({
  id: `f-${name}`, entity_id: 'e-1', name, display_name: name, field_type, options, sort_order: 0, is_required: false,
});

describe('AdvancedFindPanelComponent (U12 Phase A)', () => {
  let getSchema: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    getSchema = vi.fn().mockReturnValue(of({
      id: 'e-1', name: 'Ticket', plural_name: 'Tickets', relationships: [],
      fields: [
        field('title', 'text'),
        field('status', 'choice', { choices: ['open', 'closed'], multi: false }),
        field('attachment', 'file'),
      ],
    }));
    TestBed.configureTestingModule({
      imports: [AdvancedFindPanelComponent],
      providers: [
        { provide: EntityService, useValue: { getSchema, lookupSearch: vi.fn(), get: vi.fn() } },
        { provide: LangService, useValue: { intlLocale: () => 'en-US', translate: (key: string) => key } },
      ],
    });
  });

  function render(filters: QueryFilter[] = []) {
    const fixture = TestBed.createComponent(AdvancedFindPanelComponent);
    fixture.componentRef.setInput('entityName', 'ticket');
    fixture.componentRef.setInput('filters', filters);
    fixture.componentRef.setInput('canSave', true);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  }

  it('loads the entity fields and starts with one row', () => {
    const { cmp, el } = render();
    expect(getSchema).toHaveBeenCalledWith('ticket');
    expect(cmp.fields().map(f => f.name)).toEqual(['status', 'title']);
    expect(el.querySelectorAll('[data-testid="advanced-find-row"]').length).toBe(1);
  });

  it('offers only the attributes the list query returns', () => {
    const fixture = TestBed.createComponent(AdvancedFindPanelComponent);
    fixture.componentRef.setInput('entityName', 'ticket');
    fixture.componentRef.setInput('columnNames', ['id', 'title']);
    fixture.detectChanges();
    expect(fixture.componentInstance.fields().map(f => f.name)).toEqual(['title']);
  });

  it('applies the rows as ANDed wire filters', () => {
    const { cmp, fixture } = render();
    const emitted: QueryFilter[][] = [];
    cmp.applied.subscribe(f => emitted.push(f));
    const first = cmp.conditions()[0];
    cmp.setField(first.key, 'status');
    cmp.setOperator(first.key, 'neq');
    cmp.setValue(first.key, 'closed');
    cmp.addCondition();
    const second = cmp.conditions()[1];
    cmp.setField(second.key, 'title');
    cmp.setOperator(second.key, 'starts_with');
    cmp.setValue(second.key, 'Print');
    fixture.detectChanges();
    cmp.apply();
    expect(emitted).toEqual([[
      { field: 'status', op: 'neq', value: 'closed' },
      { field: 'title', op: 'starts_with', value: 'Print' },
    ]]);
  });

  it('opens a saved view on its filters, and Save as view emits them', () => {
    const saved: QueryFilter[] = [{ field: 'title', op: 'contains', value: 'x' }];
    const { cmp } = render(saved);
    expect(cmp.conditions().map(c => c.draft)).toEqual([{ operator: 'contains', value: 'x' }]);
    const emitted: QueryFilter[][] = [];
    cmp.saveAsView.subscribe(f => emitted.push(f));
    cmp.save();
    expect(emitted).toEqual([saved]);
  });

  it('stops adding rows at the server limit', () => {
    const { cmp } = render();
    for (let i = 0; i < 60; i++) cmp.addCondition();
    expect(cmp.conditions().length).toBe(50);
    expect(cmp.canAdd()).toBe(false);
  });

  it('Clear empties the rows and applies nothing', () => {
    const { cmp } = render([{ field: 'title', op: 'contains', value: 'x' }]);
    const emitted: QueryFilter[][] = [];
    cmp.applied.subscribe(f => emitted.push(f));
    cmp.clear();
    expect(cmp.conditions()).toEqual([]);
    expect(emitted).toEqual([[]]);
  });
});
