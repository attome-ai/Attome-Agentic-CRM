import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { RecordTypeOption, RecordTypePickerComponent } from './record-type-picker.component';

const TYPES: RecordTypeOption[] = [
  { code: 'service', label_en: 'Service', label_ar: 'خدمة', form: null, is_default: true },
  { code: 'complaint', label_en: 'Complaint', label_ar: 'شكوى', form: 'f-1', is_default: false },
];

describe('RecordTypePickerComponent (A27-T4)', () => {
  function setUp(get: () => unknown, lang = 'en') {
    TestBed.configureTestingModule({
      imports: [RecordTypePickerComponent],
      providers: [
        { provide: ApiService, useValue: { get: vi.fn(get) } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal(lang) } },
      ],
    });
    const fixture = TestBed.createComponent(RecordTypePickerComponent);
    fixture.componentRef.setInput('entity', 'case');
    fixture.detectChanges();
    const picked: (string | null)[] = [];
    fixture.componentInstance.create.subscribe(code => picked.push(code));
    return { fixture, root: fixture.nativeElement as HTMLElement, picker: fixture.componentInstance, picked };
  }

  it('is the plain New button when the entity has no types', () => {
    const { root, picked } = setUp(() => of({ items: [], total: 0, page: 1, page_size: 1 }));
    expect(root.querySelector('[data-record-type-toggle]')).toBeNull();
    (root.querySelector('[data-record-type-new]') as HTMLButtonElement).click();
    expect(picked).toEqual([null]);
  });

  it('creates the default type first and offers the others', () => {
    const { fixture, root, picked } = setUp(() => of({ items: TYPES, total: 2, page: 1, page_size: 2 }));
    (root.querySelector('[data-record-type-new]') as HTMLButtonElement).click();
    expect(picked).toEqual(['service']);
    (root.querySelector('[data-record-type-toggle]') as HTMLButtonElement).click();
    fixture.detectChanges();
    (root.querySelector('[data-record-type="complaint"]') as HTMLButtonElement).click();
    expect(picked).toEqual(['service', 'complaint']);
  });

  it('names the types in Arabic', () => {
    const { picker } = setUp(() => of({ items: TYPES, total: 2, page: 1, page_size: 2 }), 'ar');
    expect(picker.label(TYPES[1])).toBe('شكوى');
  });

  it('falls back to the plain button when the list is refused', () => {
    const { root } = setUp(() => throwError(() => ({ kind: 'forbidden', status: 403, message: '' })));
    expect(root.querySelector('[data-record-type-toggle]')).toBeNull();
    expect(root.querySelector('[data-record-type-new]')).not.toBeNull();
  });
});
