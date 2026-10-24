import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { PageDataService } from '@attome/xrm/core/page-runtime';
import type { PageDoc } from '@attome/xrm/core/page-runtime';
import { ModelService } from '@attome/xrm/model';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { PageDesignerComponent, QUERY_BUDGET, expectedQueries, freshId } from './page-designer.component';

const PAGE: PageDoc = {
  page_type: 'custom', title_en: 'Home', title_ar: 'الرئيسية',
  root: { id: 'main', type: 'container', children: [{ id: 'hello', type: 'text', props: { text_en: 'Hello' } }] },
};

describe('page designer helpers (T2-T3)', () => {
  it('counts the reads a page makes and finds a free id', () => {
    const many: PageDoc = {
      page_type: 'record',
      root: { id: 'main', type: 'container', children: Array.from({ length: QUERY_BUDGET }, (_, i) => ({ id: `l${i}`, type: 'list' as const, binding: { view: `v${i}` } })) },
    };
    expect(expectedQueries(many)).toHaveLength(QUERY_BUDGET + 1);
    expect(expectedQueries(PAGE)).toEqual([]);
    expect(freshId(PAGE, 'text')).toBe('text_1');
  });
});

describe('PageDesignerComponent (T2-T3)', () => {
  let model: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    model = {
      object: vi.fn(() => of({ id: 'p1', kind: 'page', name: 'home', version_no: 3, kind_schema_version: 1, state: 'draft', doc: PAGE, content_hash: 'h3', created_at: '' })),
      saveDraft: vi.fn(() => of({ id: 'p1', version_no: 4, content_hash: 'h4', issues: [] })),
      publish: vi.fn(() => of({ id: 'p1', version_no: 4 })),
    };
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [PageDesignerComponent],
      providers: [
        { provide: ModelService, useValue: model },
        { provide: PageDataService, useValue: { myRoles: () => of(['Mine']), rows: () => of({ records: [], total: 0 }), page: vi.fn(), record: vi.fn(), startFlow: vi.fn(), runAction: vi.fn() } },
        { provide: EntityService, useValue: { getSchema: () => of(null) } },
        { provide: Router, useValue: { navigateByUrl: vi.fn() } },
        { provide: LangService, useValue: { translate: (k: string) => k, isRtl: () => false, errorText: () => 'failed', intlLocale: () => 'en-US' } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(PageDesignerComponent);
    fixture.componentRef.setInput('id', 'p1');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  it('adds from the palette, binds it, counts its read and previews it', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    expect(model['object']).toHaveBeenCalledWith('page', 'p1');
    (root.querySelector('[data-add="list"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    const c = fixture.componentInstance;
    expect(c.current()?.root.children?.map(n => n.id)).toEqual(['hello', 'list_1']);
    expect(c.selectedPath()).toBe('/root/children/1');
    c.setBinding('view', 'v-deals');
    fixture.detectChanges();
    expect(c.current()?.root.children?.[1].binding).toEqual({ view: 'v-deals' });
    expect(c.queries()).toEqual([{ node: 'list_1', what: 'view v-deals' }]);
    expect(root.querySelector('[data-testid="pd-preview"] [data-node="list_1"]')).not.toBeNull();
  });

  it('warns above the read budget', () => {
    const fixture = render();
    const c = fixture.componentInstance;
    for (let i = 0; i <= QUERY_BUDGET; i++) {
      c.onSelect(['/root']);
      c.add('metric');
      c.setBinding('query', `q${i}`);
    }
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[data-testid="pd-query-warning"]')).not.toBeNull();
  });

  it('saves the canvas commands against the draft hash and previews by role, size and language', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    const c = fixture.componentInstance;
    c.add('button');
    c.addEvent();
    c.newTarget.set('/xrm/home');
    c.addEvent();
    fixture.detectChanges();
    (root.querySelector('[data-testid="canvas-save"]') as HTMLButtonElement).click();
    expect(model['saveDraft']).toHaveBeenCalledTimes(1);
    const [kind, id, hash, name, commands] = model['saveDraft'].mock.calls[0];
    expect([kind, id, hash, name]).toEqual(['page', 'p1', 'h3', null]);
    expect(commands.map((x: { op: string }) => x.op)).toEqual(['add', 'set']);
    expect(c.hash()).toBe('h4');

    c.rolesText.set('Finance, Sales');
    c.device.set('phone');
    c.language.set('ar');
    fixture.detectChanges();
    expect(c.previewRoles()).toEqual(['Finance', 'Sales']);
    expect(root.querySelector('[data-testid="pd-preview"]')?.classList).toContain('pd-preview--phone');
    expect(root.querySelector('[data-testid="pd-preview"] [data-testid="page-runtime"]')?.getAttribute('dir')).toBe('rtl');
  });

  it('a new page sends its base document first', () => {
    model['object'].mockReturnValue(throwError(() => ({ status: 404, kind: 'not_found' })));
    const fixture = render();
    const c = fixture.componentInstance;
    c.add('text');
    c.save([{ op: 'add', path: '/root/children/-', value: { id: 'text_1', type: 'text' } }]);
    const [, , hash, name, commands] = model['saveDraft'].mock.calls[0];
    expect(hash).toBe('');
    expect(name).toBe('page');
    expect(commands.slice(0, 2)).toEqual([{ op: 'set', path: '/page_type', value: 'custom' }, { op: 'set', path: '/title_en', value: '' }]);
  });
});
