import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { PortalPageHostComponent, replyOf } from './portal-pages.component';
import { PortalShellComponent, navigation } from './portal-shell.component';
import { PortalSiteService, portalFilters } from './portal-site.service';

const LANG = {
  translate: (k: string) => k,
  isRtl: () => false,
  current: signal('en'),
  errorText: () => 'failed',
  intlLocale: () => 'en-US',
  toggle: vi.fn(),
};

const PAGES = {
  items: [
    { name: 'portal-cases', page_type: 'portal', title_en: 'My cases', title_ar: 'حالاتي' },
    { name: 'portal-case', page_type: 'record', title_en: 'Case', title_ar: 'الحالة' },
    { name: 'portal-home', page_type: 'portal', title_en: 'Home', title_ar: 'الرئيسية' },
  ],
  total: 3, page: 1, page_size: 100,
};

const CASE_PAGE = {
  id: 'p1', name: 'portal-case', entity_name: 'service_ticket',
  doc: {
    page_type: 'record', title_en: 'Case',
    root: {
      id: 'main', type: 'container', props: { reply: { entity: 'case_message', lookup: 'case_ref', body: 'body' } },
      children: [{ id: 'messages', type: 'timeline', binding: { entity: 'case_message', related_by: 'case_ref' } }],
    },
  },
};

describe('portal site (G12-T1)', () => {
  it('lists the navigable pages, home first, without record pages', () => {
    expect(navigation(PAGES.items).map(p => p.name)).toEqual(['portal-home', 'portal-cases']);
  });

  it('turns a binding into portal filters, equality only', () => {
    expect(portalFilters({ entity: 'case_message', related_by: 'case_ref' }, 'c1')).toEqual({ case_ref: 'c1' });
    expect(portalFilters({ entity: 'service_ticket', where: [{ field: 'status', op: 'eq', value: 'open' }] }, null))
      .toEqual({ status: 'open' });
    expect(portalFilters({ entity: 'x', where: [{ field: 's', op: 'in', value: ['a'] }] }, null)).toBeNull();
    expect(portalFilters({ entity: 'x', related_by: 'r' }, null)).toBeNull();
  });

  it('reads a reply target only when it is well formed', () => {
    expect(replyOf(CASE_PAGE.doc as never)).toEqual({ entity: 'case_message', lookup: 'case_ref', body: 'body' });
    expect(replyOf({ ...CASE_PAGE.doc, root: { id: 'm', type: 'container', props: { reply: { entity: 'x; drop' } } } } as never)).toBeNull();
    expect(replyOf(null)).toBeNull();
  });
});

describe('PortalShellComponent (G12-T1)', () => {
  function create(signedIn: boolean, accepted = true) {
    const get = vi.fn((path: string) => {
      if (path.endsWith('/me')) {
        return signedIn ? of({ id: 'u1', name: 'Sara', email: null, username: null, row_version: 1, profile: {} })
          : throwError(() => ({ status: 401, kind: 'unauthorized' }));
      }
      if (path.endsWith('/me/consent')) return of({ terms_version: '1', privacy_version: '1', accepted });
      if (path.endsWith('/pages')) return of(PAGES);
      return of(null);
    });
    const post = vi.fn(() => of({}));
    TestBed.configureTestingModule({
      imports: [PortalShellComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: LANG },
      ],
    });
    TestBed.inject(PortalSiteService).keyword.set('acme');
    const router = TestBed.inject(Router);
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    const fixture = TestBed.createComponent(PortalShellComponent);
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return { fixture, get, post, navigate, root: fixture.nativeElement as HTMLElement };
  }

  it('signs a person in and shows the portal pages through the portal API', () => {
    const { get, root } = create(true);
    expect(get).toHaveBeenCalledWith('/acme/api/v1/me');
    expect(get).toHaveBeenCalledWith('/acme/api/v1/pages');
    const links = Array.from(root.querySelectorAll('[data-page]')).map(a => a.getAttribute('data-page'));
    expect(links).toEqual(['portal-home', 'portal-cases']);
    expect(root.textContent).toContain('Sara');
  });

  it('sends a person with no session to the sign-in page, and one without consent to consent', () => {
    expect(create(false).navigate).toHaveBeenCalledWith(['/p', 'acme', 'login']);
    TestBed.resetTestingModule();
    expect(create(true, false).navigate).toHaveBeenCalledWith(['/p', 'acme', 'consent']);
  });

  it('signs out through the portal', () => {
    const { fixture, post, navigate, root } = create(true);
    (root.querySelector('[data-sign-out]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/acme/api/v1/auth/logout', {});
    expect(navigate).toHaveBeenCalledWith(['/p', 'acme', 'login']);
  });
});

describe('PortalPageHostComponent (G12-T1)', () => {
  it('draws a record page from portal data and posts a reply naming the record', () => {
    const get = vi.fn((path: string, params?: Record<string, string>) => {
      if (path.endsWith('/pages/portal-case')) return of(CASE_PAGE);
      if (path.endsWith('/records/service_ticket/t1')) return of({ id: 't1', row_version: 1, created_at: null, data: { title: 'Broken' } });
      if (path.endsWith('/records/case_message')) {
        expect(params?.['case_ref']).toBe('t1');
        return of({ items: [{ id: 'm1', row_version: 1, created_at: null, data: { body: 'Hello' } }], total: 1, page: 1, page_size: 50 });
      }
      return of(null);
    });
    const post = vi.fn(() => of({ id: 'm2' }));
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [PortalPageHostComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: LANG },
      ],
    });
    TestBed.inject(PortalSiteService).keyword.set('acme');
    const fixture = TestBed.createComponent(PortalPageHostComponent);
    fixture.componentRef.setInput('page', 'portal-case');
    fixture.componentRef.setInput('id', 't1');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;
    expect(get).toHaveBeenCalledWith('/acme/api/v1/pages/portal-case');
    expect(root.querySelector('[data-node="messages"]')?.textContent).toContain('Hello');

    fixture.componentInstance.text.set('Any news?');
    fixture.detectChanges();
    (root.querySelector('[data-send]') as HTMLButtonElement).click();
    expect(post).toHaveBeenCalledWith('/acme/api/v1/records/case_message', { case_ref: 't1', body: 'Any news?' });
  });
});
