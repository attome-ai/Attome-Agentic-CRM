import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { ApiUsageService, MAX_KEY_QUOTA } from '@attome/xrm/core/admin/data';
import type { ApiKeyUsageRow } from '@attome/xrm/core/admin/data';
import { ApiUsageComponent, parseQuota } from './api-usage.component';

const key = (overrides: Partial<ApiKeyUsageRow> = {}): ApiKeyUsageRow => ({
  id: 'k1', name: 'ERP sync', public_key: 'atk_pub_1', owner_id: 'u1', owner_name: 'Huda',
  is_active: true, expires_at: null, last_used_at: null, requests_per_minute: null, total_requests: 1200,
  ...overrides,
});

describe('parseQuota (S10-T1)', () => {
  it('accepts a whole number in range or an empty field', () => {
    expect(parseQuota('')).toEqual({ ok: true, value: null });
    expect(parseQuota(' 60 ')).toEqual({ ok: true, value: 60 });
    expect(parseQuota(String(MAX_KEY_QUOTA))).toEqual({ ok: true, value: MAX_KEY_QUOTA });
    expect(parseQuota('0').ok).toBe(false);
    expect(parseQuota('1.5').ok).toBe(false);
    expect(parseQuota('-3').ok).toBe(false);
    expect(parseQuota(String(MAX_KEY_QUOTA + 1)).ok).toBe(false);
  });
});

describe('ApiUsageComponent (S10-T1)', () => {
  let svc: {
    keys: ReturnType<typeof vi.fn>;
    summary: ReturnType<typeof vi.fn>;
    setQuota: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      keys: vi.fn(() => of({ items: [key()], total: 1, page: 1, page_size: 50 })),
      summary: vi.fn(() => of({
        items: [{ method: 'GET', route_template: '/api/v1/{entity}', identity_kind: 'api_key', identity_label: 'k1', total_requests: 900 }],
        total: 1, page: 1, page_size: 50,
      })),
      setQuota: vi.fn((id: string, rpm: number | null) => of({ id, requests_per_minute: rpm })),
    };
    TestBed.configureTestingModule({
      imports: [ApiUsageComponent],
      providers: [
        { provide: ApiUsageService, useValue: svc },
        { provide: LangService, useValue: { translate: (k: string) => k, intlLocale: () => 'en-US' } },
      ],
    });
  });

  async function render() {
    const fixture = TestBed.createComponent(ApiUsageComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    return fixture;
  }

  it('lists keys with their usage and names the key on its routes', async () => {
    const root: HTMLElement = (await render()).nativeElement;
    expect(svc.keys).toHaveBeenCalledWith(7, 1, 50);
    expect(svc.summary).toHaveBeenCalledWith(7);
    expect(root.querySelector('[data-usage-key]')?.textContent).toContain('ERP sync');
    expect(root.querySelector('[data-usage-route]')?.textContent).toContain('ERP sync');
  });

  it('sets a quota per key', async () => {
    const fixture = await render();
    const c = fixture.componentInstance;
    c.setDraft('k1', '120');
    c.saveQuota(c.keys()[0]);
    expect(svc.setQuota).toHaveBeenCalledWith('k1', 120);
    expect(c.keys()[0].requests_per_minute).toBe(120);
    expect(c.notice()).toBe('apiUsage.quotaSaved');
    expect(c.changed(c.keys()[0])).toBe(false);
  });

  it('clears a quota with an empty field and refuses a bad one', async () => {
    svc.keys.mockReturnValue(of({ items: [key({ requests_per_minute: 30 })], total: 1, page: 1, page_size: 50 }));
    const fixture = await render();
    const c = fixture.componentInstance;
    c.setDraft('k1', 'abc');
    c.saveQuota(c.keys()[0]);
    expect(svc.setQuota).not.toHaveBeenCalled();
    expect(c.invalidId()).toBe('k1');
    c.setDraft('k1', '');
    c.saveQuota(c.keys()[0]);
    expect(svc.setQuota).toHaveBeenCalledWith('k1', null);
    expect(c.notice()).toBe('apiUsage.quotaCleared');
  });

  it('reloads for another window', async () => {
    const fixture = await render();
    fixture.componentInstance.setDays(30);
    expect(svc.keys).toHaveBeenLastCalledWith(30, 1, 50);
    expect(svc.summary).toHaveBeenLastCalledWith(30);
  });
});
