import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { PageDataService, bindingFilters } from './page-data.service';
import { PageDoc, fillTarget, isVisible } from './page-model';
import { PageRuntimeComponent } from './page-runtime.component';

const FLOW = '0190a8a0-0000-7000-8000-0000000000f2';

const page = (children: PageDoc['root']['children']): PageDoc => ({
  page_type: 'record', title_en: 'Account', title_ar: 'الحساب',
  root: { id: 'main', type: 'container', children },
});

describe('page model (T2-T2)', () => {
  it('navigates only inside the app', () => {
    expect(fillTarget('/xrm/contact/{id}', 'c1')).toBe('/xrm/contact/c1');
    expect(fillTarget('https://evil.example/x', 'c1')).toBeNull();
    expect(fillTarget('//evil.example', null)).toBeNull();
    expect(fillTarget('/xrm/contact/{id}', null)).toBeNull();
  });

  it('a condition that cannot be decided hides the component', () => {
    const node = { id: 'n', type: 'text' as const, props: { visible: { when: { field: 'status', op: 'eq' as const, value: 'open' } } } };
    expect(isVisible(node, { roles: [], device: 'desktop', holds: () => null })).toBe(false);
    expect(isVisible(node, { roles: [], device: 'desktop', holds: () => true })).toBe(true);
  });
});

describe('PageRuntimeComponent (T2-T2)', () => {
  let data: Record<string, ReturnType<typeof vi.fn>>;
  let navigateByUrl: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    navigateByUrl = vi.fn(() => Promise.resolve(true));
    data = {
      page: vi.fn(),
      myRoles: vi.fn(() => of(['Sales Rep'])),
      rows: vi.fn((b: { view?: string }) => (b.view === 'broken'
        ? throwError(() => ({ status: 500, kind: 'internal' }))
        : of({ records: [{ id: 'r1', name: 'Acme', amount: 1200 }, { id: 'r2', name: 'Globex', amount: 300 }], total: 2 }))),
      record: vi.fn(() => of({ status: 'open', name: 'Acme' })),
      startFlow: vi.fn(() => of({})),
      runAction: vi.fn(() => of({})),
    };
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [PageRuntimeComponent],
      providers: [
        { provide: PageDataService, useValue: data },
        { provide: Router, useValue: { navigateByUrl } },
        { provide: EntityService, useValue: { getSchema: () => of({ id: 'e', name: 'Account', plural_name: 'Accounts', fields: [{ id: 'f', entity_id: 'e', name: 'status', display_name: 'Status', field_type: 'text', options: null, sort_order: 0, is_required: false }], relationships: [] }) } },
        { provide: LangService, useValue: { translate: (k: string) => k, isRtl: () => false, errorText: () => 'failed', intlLocale: () => 'en-US' } },
      ],
    });
  });

  function render(doc: PageDoc, record = true) {
    const fixture = TestBed.createComponent(PageRuntimeComponent);
    fixture.componentRef.setInput('page', doc);
    if (record) {
      fixture.componentRef.setInput('entity', 'account');
      fixture.componentRef.setInput('record', 'a1');
    }
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  const node = (root: HTMLElement, id: string) => root.querySelector(`[data-node="${id}"]`) as HTMLElement | null;

  it('renders the palette and keeps a broken component contained', () => {
    const fixture = render(page([
      { id: 'intro', type: 'text', props: { text_en: 'Welcome' } },
      { id: 'deals', type: 'list', binding: { view: 'broken' } },
      { id: 'total', type: 'metric', binding: { query: 'q1' } },
      { id: 'by_name', type: 'chart', binding: { query: 'q1' }, props: { title_en: 'By name' } },
      { id: 'more', type: 'tabs', children: [
        { id: 'tab_a', type: 'text', props: { title_en: 'A', text_en: 'First' } },
        { id: 'tab_b', type: 'text', props: { title_en: 'B', text_en: 'Second' } },
      ] },
    ]));
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('h1')?.textContent).toContain('Account');
    expect(node(root, 'intro')?.textContent).toContain('Welcome');
    expect(node(root, 'deals')?.querySelector('[data-node-error]')).not.toBeNull();
    expect(node(root, 'total')?.querySelector('[data-metric]')?.textContent).toContain('1,200');
    expect(node(root, 'by_name')?.querySelector('attome-dashboard-chart')).not.toBeNull();
    expect(node(root, 'tab_a')?.textContent).toContain('First');
    expect(node(root, 'tab_b')).toBeNull();
  });

  it('shows components by role, device and a condition on the record', () => {
    const fixture = render(page([
      { id: 'for_sales', type: 'text', props: { text_en: 's', visible: { roles: ['Sales Rep'] } } },
      { id: 'for_finance', type: 'text', props: { text_en: 'f', visible: { roles: ['Finance'] } } },
      { id: 'phone_only', type: 'text', props: { text_en: 'p', visible: { devices: ['phone'] } } },
      { id: 'when_open', type: 'text', props: { text_en: 'o', visible: { when: { field: 'status', op: 'eq', value: 'open' } } } },
      { id: 'when_closed', type: 'text', props: { text_en: 'c', visible: { when: { field: 'status', op: 'eq', value: 'closed' } } } },
    ]));
    const root: HTMLElement = fixture.nativeElement;
    expect(node(root, 'for_sales')).not.toBeNull();
    expect(node(root, 'for_finance')).toBeNull();
    expect(node(root, 'phone_only')).toBeNull();
    expect(node(root, 'when_open')).not.toBeNull();
    expect(node(root, 'when_closed')).toBeNull();
  });

  it('a row selection navigates with its id; a button starts its flow', () => {
    const fixture = render(page([
      { id: 'list', type: 'list', binding: { view: 'v1' }, events: [{ on: 'select', do: 'navigate', target: '/xrm/entity/deal/form?id={id}' }] },
      { id: 'renew', type: 'button', props: { label_en: 'Renew' }, binding: { record: 'current' }, events: [{ on: 'click', do: 'start_flow', target: FLOW }] },
    ]));
    const root: HTMLElement = fixture.nativeElement;
    (node(root, 'list')?.querySelector('tbody tr') as HTMLElement).click();
    expect(navigateByUrl).toHaveBeenCalledWith('/xrm/entity/deal/form?id=r1');
    (node(root, 'renew') as HTMLButtonElement).click();
    expect(data['startFlow']).toHaveBeenCalledWith(FLOW, 'account', 'a1');
  });

  it('lists records related to the page record and hides an entity not installed (D1-T2)', () => {
    data['rows'].mockImplementation((b: { entity?: string }) => (b.entity === 'invoice'
      ? throwError(() => ({ status: 404, kind: 'not_found' }))
      : of({ records: [{ id: 'c1', full_name: 'Sara', amount: 5 }], total: 3 })));
    const contacts = { entity: 'contact', related_by: 'account_ref' };
    const fixture = render(page([
      { id: 'contacts', type: 'list', binding: contacts },
      { id: 'count', type: 'metric', binding: contacts },
      { id: 'invoices', type: 'list', binding: { entity: 'invoice', related_by: 'account_ref' } },
    ]));
    const root: HTMLElement = fixture.nativeElement;
    expect(data['rows']).toHaveBeenCalledWith(contacts, 'a1');
    expect(node(root, 'contacts')?.textContent).toContain('Sara');
    expect(node(root, 'count')?.querySelector('[data-metric]')?.textContent).toContain('3');
    expect(node(root, 'invoices')).toBeNull();
  });

  it('turns a binding into query filters', () => {
    expect(bindingFilters({ entity: 'opportunity', related_by: 'account_ref', where: [{ field: 'stage', op: 'in', value: ['proposal'] }] }, 'a1'))
      .toEqual([{ field: 'account_ref', op: 'eq', value: 'a1' }, { field: 'stage', op: 'in', value: ['proposal'] }]);
    expect(bindingFilters({ view: 'v1' }, 'a1')).toEqual([]);
  });

  it('loads a published page by id and says when there is none', () => {
    data['page'].mockReturnValue(throwError(() => ({ status: 404, kind: 'not_found' })));
    const fixture = TestBed.createComponent(PageRuntimeComponent);
    fixture.componentRef.setInput('id', 'p404');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    expect(data['page']).toHaveBeenCalledWith('p404');
    expect(fixture.nativeElement.querySelector('[role="alert"]')?.textContent).toContain('pageRuntime.notFound');
  });
});
