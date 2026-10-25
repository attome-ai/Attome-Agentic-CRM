import { Type, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { SeoPanelComponent } from '../content-page/form/seo-panel/seo-panel.component';
import { RobotsEditorComponent } from './robots-editor.component';
import { SeoTopicsPageComponent } from './seo-topics-page.component';
import { clip, displayLength, isArabic, lengthState, lineChanges } from './seo-text';

const LANG = {
  translate: (k: string) => k, current: signal('en'), errorText: () => 'error', intlLocale: () => 'en-US',
};

const VIEW = {
  settings: {
    title: 'Pricing for small teams', description: null, canonical_url: null,
    noindex: false, nofollow: false, og_title: null, og_description: null,
  },
  row_version: 3,
};

function setup<T>(component: Type<T>, api: Record<string, unknown>) {
  TestBed.configureTestingModule({
    imports: [component],
    providers: [
      { provide: ApiService, useValue: api },
      { provide: LangService, useValue: LANG },
    ],
  });
  return TestBed.createComponent(component);
}

describe('seo-text (E13-T12)', () => {
  it('counts what a reader sees, not combining marks', () => {
    expect(displayLength('مَرْحَبًا')).toBe(5);
    expect(displayLength('')).toBe(0);
    expect(displayLength(null)).toBe(0);
  });

  it('places a length in its band', () => {
    expect(lengthState(0, 30, 60)).toBe('empty');
    expect(lengthState(10, 30, 60)).toBe('short');
    expect(lengthState(45, 30, 60)).toBe('ok');
    expect(lengthState(61, 30, 60)).toBe('long');
  });

  it('spots Arabic script and clips to the preview width', () => {
    expect(isArabic('الأسعار')).toBe(true);
    expect(isArabic('Pricing')).toBe(false);
    expect(clip('abcdef', 4)).toBe('abc…');
    expect(clip('abc', 4)).toBe('abc');
  });

  it('counts robots.txt lines added and removed', () => {
    expect(lineChanges('User-agent: *\nDisallow: /a', 'User-agent: *\nDisallow: /b\nDisallow: /c'))
      .toEqual({ added: 2, removed: 1 });
  });
});

describe('SeoPanelComponent (E13-T12)', () => {
  function create() {
    const get = vi.fn((path: string) =>
      path.endsWith('/findings')
        ? of({ items: [{ id: 'f1', rule: 'missing_alt', severity: 'error', block_ref: 'b1', message_key: null }], total: 1, page: 1, page_size: 50 })
        : of(VIEW));
    const put = vi.fn(() => of({ ...VIEW, row_version: 4 }));
    const post = vi.fn(() => of({ score: 72 }));
    const fixture = setup(SeoPanelComponent, { get, put, post });
    fixture.componentRef.setInput('pageId', 'p1');
    fixture.detectChanges();
    return { fixture, get, put, post };
  }

  it('loads the settings and saves them with the row version', () => {
    const { fixture, put } = create();
    const panel = fixture.componentInstance;
    expect(panel.title).toBe('Pricing for small teams');
    expect(panel.titleState()).toBe('short');
    panel.description = '  ';
    panel.save();
    const [path, body, options] = put.mock.calls[0] as unknown as [string, Record<string, unknown>, { ifMatch: number }];
    expect(path).toBe('/api/v1/admin/content/pages/p1/seo');
    expect(body['description']).toBeNull();
    expect(options.ifMatch).toBe(3);
    expect(panel.rowVersion()).toBe(4);
  });

  it('runs the audit, shows the score and lists findings with go-to-block', () => {
    const { fixture, post } = create();
    const emitted: string[] = [];
    fixture.componentInstance.goToBlock.subscribe(id => emitted.push(id));
    fixture.componentInstance.runAudit();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/content/pages/p1/seo/audit', {});
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="seo-score"]')?.textContent).toContain('72');
    const finding = el.querySelector('li[data-rule="missing_alt"]');
    expect(finding?.textContent).toContain('missing alt');
    (finding?.querySelector('button') as HTMLButtonElement).click();
    expect(emitted).toEqual(['b1']);
  });

  it('previews an Arabic title right to left', () => {
    const { fixture } = create();
    fixture.componentInstance.title = 'أسعار الفرق الصغيرة';
    expect(fixture.componentInstance.rtl()).toBe(true);
  });
});

describe('RobotsEditorComponent (E13-T12)', () => {
  it('asks before saving and reports the line changes', () => {
    const get = vi.fn((_path: string) => of({ body: 'User-agent: *', served: 'User-agent: *\nDisallow: /portal/' }));
    const put = vi.fn(() => of({ body: 'User-agent: *\nDisallow: /tmp', served: 'served' }));
    const fixture = setup(RobotsEditorComponent, { get, put });
    const editor = fixture.componentInstance;
    editor.siteKey = ' Main ';
    editor.load();
    expect(get.mock.calls[0][0]).toContain('main');
    editor.body = 'User-agent: *\nDisallow: /tmp';
    editor.askToSave();
    expect(put).not.toHaveBeenCalled();
    expect(editor.changes()).toEqual({ added: 1, removed: 0 });
    editor.confirm();
    expect(put).toHaveBeenCalledTimes(1);
    expect(editor.confirming()).toBe(false);
    expect(editor.served()).toBe('served');
  });
});

describe('SeoTopicsPageComponent (E13-T12)', () => {
  it('adds a topic and deletes one only on the second click', () => {
    const topic = { id: 't1', name: 'Pricing', language: 'en', pillar_page_ref: null };
    const get = vi.fn((path: string) =>
      path.includes('/robots') ? of({ body: '', served: '' }) : of({ items: [topic], total: 1, page: 1, page_size: 50 }));
    const post = vi.fn(() => of({ id: 't2', name: 'Payroll', language: 'ar', pillar_page_ref: null }));
    const del = vi.fn(() => of(undefined));
    const fixture = setup(SeoTopicsPageComponent, { get, post, delete: del });
    fixture.detectChanges();
    const page = fixture.componentInstance;
    expect(page.topics().length).toBe(1);
    page.name = 'Payroll';
    page.add();
    expect(page.topics().map(t => t.id)).toEqual(['t1', 't2']);
    page.remove(page.topics()[0]);
    expect(del).not.toHaveBeenCalled();
    page.remove(page.topics()[0]);
    expect(del).toHaveBeenCalledTimes(1);
    expect(page.topics().map(t => t.id)).toEqual(['t2']);
  });
});
