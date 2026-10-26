import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ClientDetail, ClientListItem, S2sAdminService } from '../services/s2s-admin.service';
import { S2sClientListComponent, expiryInstant } from './clients.component';

const ROW: ClientListItem = {
  id: 'c-1', client_id: 'sap-erp', name: 'SAP ERP', status: 'active', rate_limit_rpm: 1000,
  last_used_at: null, created_at: '2026-10-01T00:00:00Z', key_slots: ['primary'],
  owner_user_ref: 'u-1', owner_email: 'owner@example.com', purpose: 'Nightly ledger export',
  environment: 'production', expires_at: '2027-01-31T23:59:59Z', methods: ['key', 'identity_provider'],
};

const CREATED = { id: 'c-2', client_id: 'new-client' } as ClientDetail;
const SECRET = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';

describe('S2sClientListComponent (S11-T6)', () => {
  let svc: {
    listClients: ReturnType<typeof vi.fn>;
    createClient: ReturnType<typeof vi.fn>;
    generateKey: ReturnType<typeof vi.fn>;
  };
  let writeText: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      listClients: vi.fn(() => of([ROW])),
      createClient: vi.fn(() => of(CREATED)),
      generateKey: vi.fn(() => of({
        public_id: 's2s_pub_1', slot: 'primary', secret: SECRET, expires_at: null, created_at: '',
      })),
    };
    writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    TestBed.configureTestingModule({
      imports: [S2sClientListComponent],
      providers: [
        provideRouter([]),
        { provide: S2sAdminService, useValue: svc },
        {
          provide: LangService,
          useValue: {
            translate: (k: string) => k, errorText: () => 'error',
            current: signal('en'), intlLocale: () => 'en-US',
          },
        },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(S2sClientListComponent);
    fixture.detectChanges();
    return fixture;
  }

  it('lists clients with owner, purpose, methods and expiry', () => {
    const el: HTMLElement = render().nativeElement;
    const row = el.querySelector('[data-client-row]')!;
    expect(row.textContent).toContain('owner@example.com');
    expect(row.textContent).toContain('Nightly ledger export');
    expect(row.textContent).toContain('s2sClients.methods.key');
    expect(row.textContent).toContain('s2sClients.methods.identity_provider');
    expect(row.textContent).toContain('Jan 31, 2027');
  });

  it('shows the new secret once, copies it, and forgets it when dismissed', async () => {
    const fixture = render();
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    const cmp = fixture.componentInstance;
    cmp.toggleCreate();
    cmp.newClientId = 'new-client';
    cmp.newName = 'New';
    cmp.newExpiry = '2027-03-01';
    cmp.create();
    fixture.detectChanges();

    expect(svc.createClient).toHaveBeenCalledWith(expect.objectContaining({
      client_id: 'new-client', name: 'New', expires_at: '2027-03-01T23:59:59.000Z',
    }));
    expect(svc.generateKey).toHaveBeenCalledWith('c-2', { slot: 'primary' });
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-secret]')?.textContent).toContain(SECRET);

    (el.querySelector('[data-copy]') as HTMLButtonElement).click();
    await Promise.resolve();
    expect(writeText).toHaveBeenCalledWith(SECRET);

    (el.querySelector('[data-dismiss]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('[data-secret-once]')).toBeNull();
    expect(el.textContent).not.toContain(SECRET);
    expect(cmp.issued()).toBeNull();
    expect(navigate).toHaveBeenCalledWith(['/xrm/admin/s2s/clients', 'c-2']);
  });

  it('refuses a client without an ID or name and sends nothing', () => {
    const cmp = render().componentInstance;
    cmp.toggleCreate();
    cmp.create();
    expect(cmp.createError()).toBe('s2sClients.required');
    expect(svc.createClient).not.toHaveBeenCalled();
  });

  it('turns a day into the end of that day, and no day into no expiry', () => {
    expect(expiryInstant('2027-03-01')).toBe('2027-03-01T23:59:59.000Z');
    expect(expiryInstant('')).toBeUndefined();
  });
});
