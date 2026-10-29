import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Observable, of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiService, LangService, PASSKEY_BROWSER } from '@attome/base';
import { ConfirmService } from '@attome/base/dialog';
import { StepUpService } from '@attome/base/step-up';

import { PASSKEY_MANAGE, PasskeysComponent } from './passkeys.component';

vi.setConfig({ testTimeout: 30_000 });

describe('PasskeysComponent', () => {
  let fixture: ComponentFixture<PasskeysComponent>;
  let api: Record<string, ReturnType<typeof vi.fn>>;
  let browser: { supported: () => boolean; create: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> };
  let stepUp: { run: ReturnType<typeof vi.fn> };
  let confirm: ReturnType<typeof vi.fn>;

  const passkey = (id: string, label: string | null) => ({
    id, label, transports: ['internal'], created_at: '2026-10-29T08:00:00Z', last_used_at: null,
  });
  const page = (items: unknown[]) => of({ items, total: items.length, page: 1, page_size: 200 });
  const el = () => fixture.nativeElement as HTMLElement;

  async function render() {
    await TestBed.configureTestingModule({
      imports: [PasskeysComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: PASSKEY_BROWSER, useValue: browser },
        { provide: StepUpService, useValue: stepUp },
        { provide: ConfirmService, useValue: { confirm } },
        {
          provide: LangService,
          useValue: { translate: (key: string) => key, errorText: () => 'error', intlLocale: () => 'en-US' },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(PasskeysComponent);
    fixture.detectChanges();
  }

  beforeEach(() => {
    TestBed.resetTestingModule();
    api = {
      get: vi.fn().mockReturnValue(page([passkey('p1', 'Work laptop')])),
      post: vi.fn((path: string): Observable<unknown> =>
        path.endsWith('/register/start') ? of({ options: { challenge: 'abc' } }) : of({ id: 'p2' })),
      delete: vi.fn().mockReturnValue(of(undefined)),
    };
    browser = { supported: () => true, create: vi.fn().mockResolvedValue({ id: 'cred' }), get: vi.fn() };
    stepUp = { run: vi.fn((_op: string, request: () => Observable<unknown>) => request()) };
    confirm = vi.fn().mockResolvedValue(true);
  });

  it('lists the passkeys with their names', async () => {
    await render();
    expect(el().querySelectorAll('[data-testid="passkey-row"]').length).toBe(1);
    expect(el().textContent).toContain('Work laptop');
  });

  it('says so when there are none', async () => {
    api['get'].mockReturnValue(page([]));
    await render();
    expect(el().querySelector('[data-testid="passkeys-empty"]')).not.toBeNull();
  });

  it('adds a passkey through the step-up, the browser and the finish route', async () => {
    await render();
    fixture.componentInstance.label.set('  Phone  ');
    await fixture.componentInstance.add();
    expect(stepUp.run).toHaveBeenCalledWith(PASSKEY_MANAGE, expect.any(Function));
    expect(browser.create).toHaveBeenCalledWith({ challenge: 'abc' });
    expect(api['post']).toHaveBeenCalledWith('/api/v1/auth/passkeys/register/finish', {
      label: 'Phone', response: { id: 'cred' },
    });
    expect(fixture.componentInstance.notice()).toBe('passkeys.added');
    expect(api['get']).toHaveBeenCalledTimes(2);
  });

  it('treats a cancelled browser prompt as nothing happened', async () => {
    browser.create.mockRejectedValue(Object.assign(new Error('no'), { name: 'NotAllowedError' }));
    await render();
    await fixture.componentInstance.add();
    expect(fixture.componentInstance.error()).toBeNull();
    expect(api['post']).not.toHaveBeenCalledWith('/api/v1/auth/passkeys/register/finish', expect.anything());
  });

  it('shows a refused step-up as an error', async () => {
    stepUp.run.mockReturnValue(throwError(() => ({ status: 401, kind: 'reauth_required', message: 'no' })));
    await render();
    await fixture.componentInstance.add();
    expect(fixture.componentInstance.error()).toBe('error');
  });

  it('removes a passkey after confirming, stepped up', async () => {
    await render();
    await fixture.componentInstance.remove(passkey('p1', 'Work laptop'));
    expect(confirm).toHaveBeenCalled();
    expect(stepUp.run).toHaveBeenCalledWith(PASSKEY_MANAGE, expect.any(Function));
    expect(api['delete']).toHaveBeenCalledWith('/api/v1/auth/passkeys/p1');
    expect(fixture.componentInstance.notice()).toBe('passkeys.removed');
  });

  it('keeps the passkey when the removal is not confirmed', async () => {
    confirm.mockResolvedValue(false);
    await render();
    await fixture.componentInstance.remove(passkey('p1', 'Work laptop'));
    expect(api['delete']).not.toHaveBeenCalled();
  });

  it('offers no adding in a browser without passkeys', async () => {
    browser = { ...browser, supported: () => false };
    await render();
    expect(el().querySelector('[data-testid="passkey-add"]')).toBeNull();
    expect(el().querySelector('[data-testid="passkeys-unsupported"]')).not.toBeNull();
  });
});
