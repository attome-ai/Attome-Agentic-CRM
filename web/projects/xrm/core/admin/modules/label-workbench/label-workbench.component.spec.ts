import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { LabelWorkbenchComponent, oneUnitXliff } from './label-workbench.component';

describe('LabelWorkbenchComponent (A20-T3)', () => {
  const rows = [
    { key: 'entity:account', source: 'Account', target: 'حساب', status: 'stale' },
    { key: 'attribute:account.name', source: 'Name', target: null, status: 'untranslated' },
  ];

  function create() {
    const get = vi.fn().mockReturnValue(of({ items: rows }));
    const post = vi.fn().mockReturnValue(of({ imported: 1, errors: [] }));
    TestBed.configureTestingModule({
      imports: [LabelWorkbenchComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (k: string) => k } },
      ],
    });
    const fixture = TestBed.createComponent(LabelWorkbenchComponent);
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('lists the labels with their status for a language', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/admin/entities/labels/workbench', { locale: 'ar-SA' });
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('tbody tr').length).toBe(2);
    expect(el.querySelector('[data-key="entity:account"] [data-status]')?.getAttribute('data-status')).toBe('stale');
  });

  it('saves an edited translation through the XLIFF import', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    const row = c.rows()[1];
    expect(c.isDirty(row)).toBe(false);
    c.edit(row, 'الاسم');
    expect(c.isDirty(row)).toBe(true);
    c.save(row);
    const [path, body] = post.mock.calls[0];
    expect(path).toBe('/api/v1/admin/entities/labels/xliff');
    expect(body).toContain('<unit id="attribute:account.name">');
    expect(body).toContain('<target>الاسم</target>');
    expect(body).toContain('trgLang="ar-SA"');
  });

  it('escapes the text it writes', () => {
    const xml = oneUnitXliff('ar', { key: 'k', source: 'A & B', target: null, status: 'untranslated' }, '<x>');
    expect(xml).toContain('<source>A &amp; B</source>');
    expect(xml).toContain('<target>&lt;x&gt;</target>');
  });
});
