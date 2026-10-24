import { Component, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CurrencyService, LangService } from '@attome/base';
import { FieldSchema } from '@attome/xrm';

import { FieldInputComponent } from './field-input.component';
import { scanToValues } from './scan-to-values';
import { EntityService } from '../../services/entity.service';
import { FileUploadService } from '../file-upload.service';

const MOCK_CURRENCY_SERVICE = {
  preferredCurrency: signal('USD'),
  rates: signal([{ code: 'USD', icon: '$', rate: 1 }]),
  getPreferredCurrency: () => 'USD', getRates: () => [], getRate: () => ({ code: 'USD', icon: '$', rate: 1 }),
  fromBase: (n: number) => n, toBase: (n: number) => n, setPreferredCurrency: vi.fn(),
};

const GS1 = { scan: { enabled: true, formats: ['code_128'], gs1_batch_attribute: 'batch_no', gs1_expiry_attribute: 'expires_on' } };

function field(type: 'text' | 'number', options: unknown): FieldSchema {
  return {
    id: 'f', entity_id: 'e1', name: 'gtin', display_name: 'GTIN',
    field_type: type, options: options as FieldSchema['options'], sort_order: 0, is_required: false,
  };
}

@Component({
  standalone: true,
  imports: [ReactiveFormsModule, FieldInputComponent],
  template: `<form [formGroup]="form" [attr.dir]="dir"><attome-field-input [field]="field" /></form>`,
})
class HostComponent {
  field!: FieldSchema;
  dir = 'ltr';
  form = new FormGroup({
    gtin: new FormControl<string | number | null>(null),
    batch_no: new FormControl<string | null>(null),
    expires_on: new FormControl<string | null>(null),
  });
}

describe('scanToValues (B16-T4)', () => {
  it('reads GS1 into the value and its siblings', () => {
    const fill = scanToValues(']C10109501101530003' + '17261231' + '10LOT-7', 'code_128', 'text', GS1.scan);
    expect(fill).toEqual({ value: '09501101530003', siblings: { batch_no: 'LOT-7', expires_on: '2026-12-31' } });
  });
});

describe('FieldInputComponent scanning (B16-T4)', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [HostComponent],
      providers: [
        { provide: EntityService, useValue: {} },
        { provide: FileUploadService, useValue: {} },
        { provide: CurrencyService, useValue: MOCK_CURRENCY_SERVICE },
        { provide: LangService, useValue: { translate: (key: string) => key, isRtl: () => false } },
      ],
    });
  });

  function render(f: FieldSchema, dir = 'ltr') {
    const fixture = TestBed.createComponent(HostComponent);
    fixture.componentInstance.field = f;
    fixture.componentInstance.dir = dir;
    fixture.detectChanges();
    const input = fixture.debugElement.query(By.directive(FieldInputComponent)).componentInstance as FieldInputComponent;
    return { fixture, input, root: fixture.nativeElement as HTMLElement };
  }

  it('shows scan button only when options.scan.enabled', () => {
    expect(render(field('text', GS1)).root.querySelector('[data-testid="scan-button"]')).not.toBeNull();
    expect(render(field('text', { scan: { ...GS1.scan, enabled: false } })).root.querySelector('[data-testid="scan-button"]')).toBeNull();
    expect(render(field('text', null)).root.querySelector('[data-testid="scan-button"]')).toBeNull();
  });

  it('fills gs1 siblings', () => {
    const { fixture, input } = render(field('text', GS1));
    input.applyScan(']C10109501101530003' + '17261231' + '10LOT-7', 'code_128');
    const form = fixture.componentInstance.form;
    expect(form.value).toEqual({ gtin: '09501101530003', batch_no: 'LOT-7', expires_on: '2026-12-31' });
    expect(form.dirty).toBe(true);
  });

  it('rejects bad check digit', () => {
    const { fixture, input, root } = render(field('text', GS1));
    input.applyScan('4006381333932', 'ean_13');
    fixture.detectChanges();
    expect(fixture.componentInstance.form.value.gtin).toBeNull();
    expect(root.querySelector('[data-testid="scan-error"]')?.textContent).toContain('fieldInput.scan.badCheckDigit');
  });

  it('rejects a non-numeric scan into a number field', () => {
    const { fixture, input, root } = render(field('number', GS1));
    input.applyScan('ABC-1', 'code_128');
    fixture.detectChanges();
    expect(root.querySelector('[data-testid="scan-error"]')?.textContent).toContain('fieldInput.scan.notANumber');
    input.applyScan('4006381333931', 'ean_13');
    expect(fixture.componentInstance.form.value.gtin).toBe(4006381333931);
  });

  it('a keyboard-wedge value ending in Enter commits', () => {
    const { fixture, root } = render(field('text', GS1));
    const el = root.querySelector('input.xf-input') as HTMLInputElement;
    el.value = '4006381333931';
    el.dispatchEvent(new Event('input'));
    el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(fixture.componentInstance.form.value.gtin).toBe('4006381333931');
  });

  it('button is inline-end in rtl', () => {
    const { root } = render(field('text', GS1), 'rtl');
    const row = root.querySelector('.scan-row') as HTMLElement;
    // The button follows the input in a flex row, so in right to left it sits at the inline end (the left).
    expect(row.lastElementChild?.getAttribute('data-testid')).toBe('scan-button');
    expect(row.firstElementChild?.tagName).toBe('INPUT');
    expect(row.closest('[dir]')?.getAttribute('dir')).toBe('rtl');
  });
});
