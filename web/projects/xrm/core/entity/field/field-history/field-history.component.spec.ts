import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService, UserPreferencesService } from '@attome/base';
import { FieldSchema } from '@attome/xrm';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { EntityService } from '../../services/entity.service';
import { FieldHistoryComponent, controlValue, entriesFor } from './field-history.component';

const FIELD: FieldSchema = {
  id: 'f1', entity_id: 'e1', name: 'discount', display_name: 'Discount',
  field_type: 'number', options: null, sort_order: 1, is_required: false,
};

const PAGE = {
  items: [
    {
      audit_id: 'a2', changed_on: '2026-10-01T10:00:00Z', operation: 'updated',
      user_id: 'u1', user_display_name: 'Sara',
      fields: [
        { field_name: 'discount', display_name: 'Discount', field_type: 'number', old_value: '10', new_value: '25', masked: false },
        { field_name: 'name', display_name: 'Name', field_type: 'text', old_value: 'a', new_value: 'b', masked: false },
      ],
    },
    {
      audit_id: 'a1', changed_on: '2026-09-01T10:00:00Z', operation: 'updated',
      user_id: 'u2', user_display_name: null,
      fields: [{ field_name: 'name', display_name: 'Name', field_type: 'text', old_value: '', new_value: 'a', masked: false }],
    },
  ],
  next_cursor: null,
};

function setup() {
  const fieldHistory = vi.fn(() => of(PAGE));
  TestBed.configureTestingModule({
    imports: [FieldHistoryComponent],
    providers: [
      { provide: EntityService, useValue: { fieldHistory } },
      { provide: LangService, useValue: { current: signal('en'), translate: (k: string) => k, intlLocale: () => 'en-US' } },
      { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
    ],
  });
  const fixture = TestBed.createComponent(FieldHistoryComponent);
  fixture.componentRef.setInput('entityName', 'deal');
  fixture.componentRef.setInput('recordId', 'r1');
  fixture.componentRef.setInput('field', FIELD);
  fixture.detectChanges();
  return { fixture, component: fixture.componentInstance, fieldHistory };
}

describe('FieldHistoryComponent', () => {
  it('lists only this field\'s changes and restores a typed old value', () => {
    const { fixture, component, fieldHistory } = setup();
    const restored: unknown[] = [];
    component.restored.subscribe(v => restored.push(v));
    component.toggle();
    fixture.detectChanges();
    expect(fieldHistory).toHaveBeenCalledWith('deal', 'r1', 'discount');
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('[data-testid="field-history-entry"]').length).toBe(1);
    (el.querySelector('[data-testid="field-history-restore"]') as HTMLButtonElement).click();
    expect(restored).toEqual([10]);
    expect(component.open()).toBe(false);
  });

  it('types old values for the form control', () => {
    expect(controlValue('number', '12.5')).toBe(12.5);
    expect(controlValue('bool', 'true')).toBe(true);
    expect(controlValue('date', '2026-02-18T00:00:00Z')).toBe('2026-02-18');
    expect(controlValue('text', '')).toBeNull();
    expect(entriesFor(PAGE.items as never, 'name').length).toBe(2);
  });
});
