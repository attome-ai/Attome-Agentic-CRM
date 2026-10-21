import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { Customer360Component, sectionsFor } from './customer-360.component';

describe('Customer360Component (G15-T1)', () => {
  function create(entity = 'account') {
    const post = vi.fn((path: string, body: { entity?: string }) => {
      if (path.includes('record.summarize')) {
        return of({ status: 'completed', result: { summary: 'ملخص العميل' } });
      }
      if (body.entity === 'entitlement') return throwError(() => ({ kind: 'not_found', status: 404 }));
      return of({ data: { records: [{ id: 'd1', name: 'Renewal 2027' }], total: 7 } });
    });
    const get = vi.fn((_: string, __?: unknown) => of({ items: [{ kind: 'note', occurred_at: '2027-03-01T08:00:00Z', summary: 'Called the customer' }] }));
    TestBed.configureTestingModule({
      imports: [Customer360Component],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { get, post } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), errorText: () => 'error', intlLocale: () => 'en-US' },
        },
      ],
    });
    const fixture = TestBed.createComponent(Customer360Component);
    fixture.componentRef.setInput('entity', entity);
    fixture.componentRef.setInput('recordId', 'acc1');
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('loads nothing until a section opens, then its first page and count', () => {
    const { fixture, post } = create();
    expect(post).not.toHaveBeenCalled();
    const c = fixture.componentInstance;
    const deals = c.sections().find(s => s.key === 'deals');
    expect(deals).toBeDefined();
    if (!deals) return;
    c.load(deals);
    expect(post).toHaveBeenCalledWith('/api/v1/query/execute', expect.objectContaining({
      entity: 'opportunity',
      page_size: 5,
      include_total: true,
      filters: [
        { field: 'account_ref', op: 'eq', value: 'acc1' },
        { field: 'stage', op: 'in', value: ['prospecting', 'qualification', 'proposal', 'negotiation'] },
      ],
    }));
    expect(c.state('deals')).toEqual({ status: 'ready', total: 7, rows: [{ id: 'd1', label: 'Renewal 2027' }] });
  });

  it('hides a section whose entity is not installed', () => {
    const { fixture } = create();
    const c = fixture.componentInstance;
    const entitlements = c.sections().find(s => s.key === 'entitlements');
    if (!entitlements) throw new Error('no entitlements section');
    c.load(entitlements);
    fixture.detectChanges();
    expect(c.state('entitlements').status).toBe('hidden');
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-section="entitlements"]')).toBeNull();
  });

  it('asks for the AI summary on request', () => {
    const { fixture, post } = create();
    fixture.componentInstance.summarise();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/actions/record.summarize/invoke', {
      args: { entity: 'account', record_id: 'acc1' },
    });
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-summary]')?.textContent).toContain('ملخص العميل');
  });

  it('gives a contact its own sections', () => {
    expect(sectionsFor('contact', 'c1').map(s => s.key)).toEqual(['tasks', 'assets']);
    expect(sectionsFor('account', 'a1').map(s => s.key))
      .toEqual(['deals', 'tasks', 'invoices', 'entitlements', 'assets', 'contacts']);
  });
});
