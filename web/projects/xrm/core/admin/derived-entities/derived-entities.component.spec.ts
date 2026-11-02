import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService, SdkService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { DerivedEntitiesComponent, type DerivedEntityDef } from './derived-entities.component';
import { sdkFromApi } from '../../../testing/sdk-from-api';

const ITEMS: DerivedEntityDef[] = [
  { name: 'big_open_deal', anchor: 'deal', condition: 'amount > 100000', mode: 'stored' },
  { name: 'vip_account', anchor: 'account', condition: 'tier == "vip"', mode: 'live' },
];

const FLOWS = [
  { logicalname: 'welcome_mail', name: 'Welcome mail', is_active: true, published_version: 2 },
  { logicalname: 'draft_flow', name: 'Draft', is_active: true, published_version: null },
];

const PREVIEW = { matching: 42, entering: 5, leaving: 2, sample: [{ id: 'd1', name: 'Tower deal' }] };

describe('DerivedEntitiesComponent (A26-T5)', () => {
  function create() {
    const getAllPages = vi.fn((path: string) => of<unknown[]>(path.startsWith('/api/v1/workflow') ? FLOWS : ITEMS));
    const post = vi.fn((path: string, _body: unknown) =>
      of(path.endsWith('/preview') ? PREVIEW
        : path.endsWith('/mass') ? { operation: { id: 'op1', status: 'queued', rows_done: 0 } }
        : path.endsWith('/start-flow') ? { started: 7 }
        : { entered: 3, left: 1 }));
    const put = vi.fn((_: string, _body: unknown) => of(ITEMS[0]));
    const del = vi.fn(() => of(undefined));
    TestBed.configureTestingModule({
      imports: [DerivedEntitiesComponent],
      providers: [
        { provide: SdkService, useValue: sdkFromApi({ getAllPages, post, put, delete: del }) },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), isRtl: signal(false) },
        },
      ],
    });
    const fixture = TestBed.createComponent(DerivedEntitiesComponent);
    fixture.detectChanges();
    return { fixture, getAllPages, post, put, del };
  }

  it('lists derived entities from the API', () => {
    const { fixture, getAllPages } = create();
    expect(getAllPages).toHaveBeenCalledWith('/api/v1/admin/derived-entities');
    const rows = fixture.nativeElement.querySelectorAll('tr[data-derived]');
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain('amount > 100000');
    // Only a stored one can be resumed.
    expect(rows[0].textContent).toContain('derivedEntitiesPage.resume');
    expect(rows[1].textContent).not.toContain('derivedEntitiesPage.resume');
  });

  it('previews a condition with its cost', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    c.edit(ITEMS[0]);
    c.set('condition', 'amount > 50000');
    c.previewDraft();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/derived-entities/preview', {
      name: 'big_open_deal', anchor: 'deal', condition: 'amount > 50000',
    });
    const cost = fixture.nativeElement.querySelector('[data-testid="de-cost"]') as HTMLElement;
    expect(cost.textContent).toContain('derivedEntitiesPage.matching');
    expect(cost.textContent).toContain('derivedEntitiesPage.costStored');
    expect(cost.textContent).toContain('Tower deal');
    // Changing the draft drops a stale preview.
    c.set('anchor', 'account');
    expect(c.preview()).toBeNull();
  });

  it('saves, deletes and resumes', () => {
    const { fixture, put, del, post } = create();
    const c = fixture.componentInstance;
    c.edit(ITEMS[1]);
    c.save();
    expect(put).toHaveBeenCalledWith('/api/v1/admin/derived-entities/vip_account', {
      anchor: 'account', condition: 'tier == "vip"', mode: 'live',
    });
    c.remove(ITEMS[1]);
    expect(del).toHaveBeenCalledWith('/api/v1/admin/derived-entities/vip_account');
    c.resume(ITEMS[0]);
    expect(post).toHaveBeenCalledWith('/api/v1/admin/derived-entities/big_open_deal/resume', null);
    expect(c.notice()).toContain('+3');
  });

  it('reassigns the members to a team as a mass operation', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    c.acting.set('big_open_deal');
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[data-testid="de-act"]')).not.toBeNull();
    c.reassign(ITEMS[0], ' Key accounts ');
    expect(post).toHaveBeenCalledWith('/api/v1/derived-entities/big_open_deal/mass', {
      kind: 'reassign', payload: { team_name: 'Key accounts' }, reason: 'big_open_deal members',
    });
    expect(c.acting()).toBeNull();
    expect(c.notice()).toContain('queued');
  });

  it('starts a published flow on every member', () => {
    const { fixture, post, getAllPages } = create();
    const c = fixture.componentInstance;
    c.openAct('big_open_deal');
    fixture.detectChanges();
    expect(getAllPages).toHaveBeenCalledWith('/api/v1/workflow/definitions');
    // Only published flows are offered.
    const options = fixture.nativeElement.querySelectorAll('[data-testid="de-flow"] option');
    expect(options.length).toBe(1);
    expect(options[0].textContent).toContain('Welcome mail');
    c.startFlow(ITEMS[0], 'welcome_mail');
    expect(post).toHaveBeenCalledWith('/api/v1/admin/derived-entities/big_open_deal/start-flow', {
      definition: 'welcome_mail',
    });
    expect(c.acting()).toBeNull();
    expect(c.notice()).toContain('7');
  });
});
