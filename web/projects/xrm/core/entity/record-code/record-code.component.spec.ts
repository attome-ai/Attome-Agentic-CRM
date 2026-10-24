import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { FieldSchema } from '@attome/xrm';
import { beforeEach, describe, expect, it } from 'vitest';

import { RecordCodeComponent, recordLink } from './record-code.component';

const field = (name: string, field_type: 'text' | 'number' | 'date'): FieldSchema => ({
  id: name, entity_id: 'e', name, display_name: name, field_type, options: null, sort_order: 0, is_required: false,
});

describe('RecordCodeComponent (B16-T11)', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [RecordCodeComponent],
      providers: [{ provide: LangService, useValue: { translate: (k: string) => k } }],
    });
  });

  it('the link names only the entity and the id', () => {
    expect(recordLink('https://crm.example.com/', 'contact', 'abc')).toBe('https://crm.example.com/r/contact/abc');
  });

  it('draws a QR of the record link, and offers only filled text and number values', async () => {
    const fixture = TestBed.createComponent(RecordCodeComponent);
    fixture.componentRef.setInput('entity', 'product');
    fixture.componentRef.setInput('recordId', 'p1');
    fixture.componentRef.setInput('fields', [field('sku', 'text'), field('weight', 'number'), field('made', 'date'), field('note', 'text')]);
    fixture.componentRef.setInput('values', { sku: '4006381333931', weight: 2, made: '2026-01-01', note: '' });
    fixture.detectChanges();
    const c = fixture.componentInstance;
    expect(c.valueFields().map(f => f.name)).toEqual(['sku', 'weight']);
    c.toggle();
    await c.draw();
    fixture.detectChanges();
    const img = fixture.nativeElement.querySelector('[data-testid="record-code-image"]') as HTMLImageElement;
    expect(img.getAttribute('src')?.startsWith('data:image/svg+xml')).toBe(true);
    c.source.set('sku');
    c.kind.set('ean13');
    await c.draw();
    expect(c.image()).not.toBeNull();
    expect(c.error()).toBeNull();
  });
});
