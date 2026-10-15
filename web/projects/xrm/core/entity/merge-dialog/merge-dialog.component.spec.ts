import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { DuplicatesService, MergePreview } from '@attome/xrm/core/admin/data';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { EntityService } from '../services/entity.service';
import { MergeDialogComponent } from './merge-dialog.component';

describe('MergeDialogComponent (A15-T10)', () => {
  const schema = {
    id: 'e', name: 'contact', plural_name: 'contacts', relationships: [],
    fields: [
      { id: '1', entity_id: 'e', name: 'name', display_name: 'Name', field_type: 'text', options: null, sort_order: 1, is_required: false },
      { id: '2', entity_id: 'e', name: 'phone', display_name: 'Phone', field_type: 'text', options: null, sort_order: 2, is_required: false },
      { id: '3', entity_id: 'e', name: 'email', display_name: 'Email', field_type: 'text', options: null, sort_order: 3, is_required: false },
    ],
  };
  const records: Record<string, unknown> = {
    a: { id: 'a', entity_id: 'e', row_version: 4, data: { name: 'Mona', phone: '+9661', email: null } },
    b: { id: 'b', entity_id: 'e', row_version: 2, data: { name: 'Mona', phone: '+9662', email: 'm@x.sa' } },
  };
  const preview: MergePreview = {
    moved: [{ relationship: 'note.regarding', count: 3 }, { relationship: 'deal.contact', count: 2 }],
    flows: ['Welcome flow'],
    result: { name: 'Mona', phone: '+9661', email: 'm@x.sa' },
    conflicts: [],
    merge_mode: 'soft_delete',
  };

  function setUp() {
    const mergePreview = vi.fn(() => of(preview));
    const mergeRecords = vi.fn(() => of({ id: 'a', survivorship_conflicts: [], merge_log_id: 'log-1' }));
    TestBed.configureTestingModule({
      imports: [MergeDialogComponent],
      providers: [
        { provide: EntityService, useValue: { getSchema: () => of(schema), get: (_: string, id: string) => of(records[id]) } },
        { provide: DuplicatesService, useValue: { mergePreview, mergeRecords } },
        {
          provide: LangService,
          useValue: {
            translate: (key: string, params?: Record<string, unknown>) => (params ? `${key} ${JSON.stringify(params)}` : key),
            errorText: () => 'error',
            current: signal('en'),
            intlLocale: signal('en-US'),
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(MergeDialogComponent);
    fixture.componentRef.setInput('entity', 'contact');
    fixture.componentRef.setInput('survivorId', 'a');
    fixture.componentRef.setInput('mergedId', 'b');
    fixture.componentRef.setInput('candidateId', 'cand-1');
    fixture.detectChanges();
    return { fixture, dialog: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, mergePreview, mergeRecords };
  }

  it('shows preview counts before confirm', () => {
    const { el, mergeRecords } = setUp();
    expect(el.querySelector('[data-merge-moved]')?.textContent).toContain('"count":5');
    expect(el.querySelector('[data-merge-flows]')?.textContent).toContain('Welcome flow');
    expect(el.querySelector('[data-merge-confirm]')).not.toBeNull();
    expect(mergeRecords).not.toHaveBeenCalled();
  });

  it('pre-selects what survivorship keeps and sends the picks with the merge', () => {
    const { dialog, mergePreview, mergeRecords } = setUp();
    // email: survivor empty, the preview takes the merged value; phone: kept.
    expect(dialog.picks()).toEqual({ phone: 'survivor', email: 'merged' });
    expect(dialog.rows().find(r => r.name === 'name')?.same).toBe(true);

    dialog.pick('phone', 'merged');
    expect(mergePreview).toHaveBeenLastCalledWith('contact', 'a', 'b', { phone: 'merged', email: 'merged' });
    expect(dialog.result()['phone']).toBe('+9662');

    const merged: unknown[] = [];
    dialog.merged.subscribe(r => merged.push(r));
    dialog.confirm();
    expect(mergeRecords).toHaveBeenCalledWith('contact', 'a', 'b', {
      picks: { phone: 'merged', email: 'merged' }, candidateId: 'cand-1', rowVersion: 4,
    });
    expect(merged).toHaveLength(1);
  });
});
