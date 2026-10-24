import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService, UserPreferencesService } from '@attome/base';
import { MasterDataService } from '@attome/xrm/core/admin/data';
import type { MasterProvenance } from '@attome/xrm/core/admin/data';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ContributionsListComponent } from './contributions-list.component';
import { GoldenRecordPanelComponent } from './golden-record-panel.component';
import { goldenRows, shown } from './golden-rows';
import { HeldQueueComponent } from './held-queue.component';
import { XrefSearchComponent } from './xref-search.component';

const prov = (attribute: string, extra: Partial<MasterProvenance> = {}): MasterProvenance => ({
  attribute, rule: 'source_system_rank', chosen_at: '2026-10-20T09:00:00Z', pinned: false,
  contribution_id: 'c1', source_system: 'erp', external_id: 'E-1', received_at: '2026-10-20T08:00:00Z',
  ...extra,
});

describe('goldenRows (L1-T9)', () => {
  it('pairs an attribute with its Arabic twin and labels from the schema', () => {
    const rows = goldenRows(
      [{ name: 'legal_name', display_name: 'Legal name' }, { name: 'legal_name_ar', display_name: 'Legal name (Arabic)' }],
      { legal_name: 'Acme Trading', legal_name_ar: 'أكمي للتجارة', phone: '+966' },
      [prov('legal_name'), prov('legal_name_ar'), prov('phone'), prov('motto_ar')],
    );
    expect(rows.map(r => r.attribute)).toEqual(['legal_name', 'phone', 'motto_ar']);
    expect(rows[0].label).toBe('Legal name');
    expect(rows[0].arabic?.value).toBe('أكمي للتجارة');
    expect(rows[1].label).toBe('phone');
    expect(shown(null)).toBe('—');
    expect(shown(3)).toBe('3');
  });
});

function lang(rtl = false) {
  return {
    translate: (k: string, p?: Record<string, unknown>) => (p ? `${k}:${JSON.stringify(p)}` : k),
    isRtl: () => rtl,
    errorText: () => 'failed',
    intlLocale: () => (rtl ? 'ar-SA' : 'en-US'),
  };
}

describe('master data components (L1-T9)', () => {
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  function setup(rtl = false) {
    svc = {
      fields: vi.fn(() => of([{ name: 'legal_name', display_name: 'Legal name' }, { name: 'legal_name_ar', display_name: 'Arabic name' }])),
      values: vi.fn(() => of({ legal_name: 'Acme Trading', legal_name_ar: 'أكمي للتجارة' })),
      provenance: vi.fn(() => of({ items: [prov('legal_name'), prov('legal_name_ar', { pinned: true, rule: 'pinned' })], total: 2, page: 1, page_size: 2 })),
      systemIds: vi.fn(() => of({ items: [
        { contribution_id: 'c1', source_system: 'erp', external_id: 'E-1', status: 'attached', received_at: '2026-10-20T08:00:00Z' },
        { contribution_id: 'c2', source_system: 'crm', external_id: 'C-9', status: 'held', received_at: '2026-10-21T08:00:00Z' },
      ], total: 2, page: 1, page_size: 500 })),
      pin: vi.fn(() => of(undefined)),
      unpin: vi.fn(() => of(undefined)),
      detach: vi.fn(() => of({ golden_id: 'g1', rebuild_queued: true })),
      held: vi.fn(() => of({ items: [
        { entity: 'account', id: 'h1', source_system: 'erp', external_id: 'E-7', received_at: '2026-10-22T08:00:00Z', held_reason: 'phone is not valid' },
      ], total: 1, page: 1, page_size: 25 })),
      release: vi.fn(() => of({ golden_id: 'g1', rebuild_queued: true })),
      reject: vi.fn(() => of(undefined)),
      lookup: vi.fn(() => of({ golden_id: 'g1', status: 'attached' })),
    };
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [GoldenRecordPanelComponent, HeldQueueComponent, XrefSearchComponent, ContributionsListComponent],
      providers: [
        provideRouter([]),
        { provide: MasterDataService, useValue: svc },
        { provide: LangService, useValue: lang(rtl) },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
  }

  function panel(rtl = false) {
    setup(rtl);
    const fixture = TestBed.createComponent(GoldenRecordPanelComponent);
    fixture.componentRef.setInput('entityName', 'account');
    fixture.componentRef.setInput('recordId', 'g1');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  beforeEach(() => setup());

  it('shows each value with its source and rule, the Arabic twin beside it', () => {
    const root: HTMLElement = panel().nativeElement;
    const rows = root.querySelectorAll('[data-testid="golden-row"]');
    expect(rows).toHaveLength(1);
    expect(rows[0].textContent).toContain('Acme Trading');
    expect(rows[0].textContent).toContain('masterData.golden.from:{"system":"erp","id":"E-1"}');
    expect(rows[0].textContent).toContain('masterData.rules.rank');
    const ar = root.querySelector('[data-testid="golden-arabic"]') as HTMLElement;
    expect(ar.getAttribute('dir')).toBe('rtl');
    expect(ar.getAttribute('lang')).toBe('ar');
    expect(root.querySelector('[data-testid="golden-pin-ar"]')?.getAttribute('aria-pressed')).toBe('true');
    expect(root.querySelectorAll('[data-testid="contribution"]')).toHaveLength(2);
  });

  it('pins and unpins through the pin routes', () => {
    const fixture = panel();
    const root: HTMLElement = fixture.nativeElement;
    (root.querySelector('[data-testid="golden-pin"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(svc['pin']).toHaveBeenCalledWith('account', 'g1', 'legal_name');
    expect(root.querySelector('[data-testid="golden-pin"]')?.getAttribute('aria-pressed')).toBe('true');
    (root.querySelector('[data-testid="golden-pin-ar"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(svc['unpin']).toHaveBeenCalledWith('account', 'g1', 'legal_name_ar');
  });

  it('says so when a non-steward pins', () => {
    const fixture = panel();
    svc['pin'].mockReturnValue(throwError(() => ({ status: 403, kind: 'forbidden' })));
    (fixture.nativeElement.querySelector('[data-testid="golden-pin"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[data-testid="golden-error"]')?.textContent).toContain('masterData.notSteward');
  });

  it('renders in Arabic with the same structure', () => {
    const root: HTMLElement = panel(true).nativeElement;
    expect(root.querySelector('[data-testid="golden-panel"]')).not.toBeNull();
    expect(root.querySelector('[data-testid="golden-arabic"]')?.textContent).toContain('أكمي');
  });

  it('detaches an attached contribution only', () => {
    const fixture = TestBed.createComponent(ContributionsListComponent);
    fixture.componentRef.setInput('entityName', 'account');
    fixture.componentRef.setInput('recordId', 'g1');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;
    const buttons = root.querySelectorAll('[data-testid="contribution-detach"]');
    expect(buttons).toHaveLength(1);
    (buttons[0] as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(svc['detach']).toHaveBeenCalledWith('account', 'c1');
    expect(root.querySelector('[data-status="attached"]')).toBeNull();
  });

  it('releases a held contribution and rejects one with a reason', async () => {
    const fixture = TestBed.createComponent(HeldQueueComponent);
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="held-item"]')?.textContent).toContain('phone is not valid');
    (root.querySelector('[data-testid="held-reject"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    await fixture.whenStable();
    const confirm = root.querySelector('[data-testid="held-reject-confirm"]') as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fixture.componentInstance.reason.set('a duplicate of E-6');
    fixture.detectChanges();
    fixture.componentInstance.reject(fixture.componentInstance.items()[0]);
    fixture.detectChanges();
    expect(svc['reject']).toHaveBeenCalledWith('account', 'h1', 'a duplicate of E-6');
    expect(root.querySelector('[data-testid="held-item"]')).toBeNull();

    svc['held'].mockReturnValue(of({ items: [
      { entity: 'account', id: 'h2', source_system: 'crm', external_id: 'C-1', received_at: '2026-10-22T08:00:00Z' },
    ], total: 1, page: 1, page_size: 25 }));
    const again = TestBed.createComponent(HeldQueueComponent);
    again.detectChanges();
    (again.nativeElement.querySelector('[data-testid="held-release"]') as HTMLButtonElement).click();
    again.detectChanges();
    expect(svc['release']).toHaveBeenCalledWith('account', 'h2');
    expect(again.nativeElement.querySelector('[data-testid="held-notice"]')?.textContent).toContain('masterData.held.released');
  });

  it('finds the golden record of a system id, or says none is visible', () => {
    const fixture = TestBed.createComponent(XrefSearchComponent);
    fixture.detectChanges();
    const c = fixture.componentInstance;
    c.entity.set('account');
    c.system.set('erp');
    c.externalId.set('E-1');
    c.search();
    fixture.detectChanges();
    expect(svc['lookup']).toHaveBeenCalledWith('account', 'erp', 'E-1');
    const link = fixture.nativeElement.querySelector('[data-testid="xref-result"] a') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('/r/account/g1');
    svc['lookup'].mockReturnValue(throwError(() => ({ status: 404, kind: 'not_found' })));
    c.search();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[data-testid="xref-error"]')?.textContent).toContain('masterData.xref.notFound');
  });
});
