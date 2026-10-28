import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { MfaCoverageComponent } from './mfa-coverage.component';
import { SecurityAdminService } from './security-admin.service';

const lang = { translate: (k: string) => k, current: signal('ar'), errorText: () => 'error', intlLocale: () => 'ar-SA' };

describe('MFA coverage (Q5-T10)', () => {
  function create() {
    const mfaCoverage = vi.fn(() => of([
      { user_id: 'u1', email: 'admin@example.com', roles: ['System Administrator'], factors: ['totp'],
        is_admin: true, admin_missing_phishing_resistant: true },
      { user_id: 'u2', email: 'agent@example.com', roles: ['Agent'], factors: [],
        is_admin: false, admin_missing_phishing_resistant: false },
    ]));
    const svc = {
      listRoles: vi.fn(() => of([{ id: 'r1', name: 'Agent' }])),
      mfaCoverageSummary: vi.fn(() => of([{ role_id: 'r1', role: 'Agent', users: 4, with_totp: 3, without_mfa: 1 }])),
      mfaCoverage,
    };
    TestBed.configureTestingModule({
      imports: [MfaCoverageComponent],
      providers: [
        { provide: SecurityAdminService, useValue: svc },
        { provide: LangService, useValue: lang },
      ],
    });
    const fixture = TestBed.createComponent(MfaCoverageComponent);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, mfaCoverage };
  }

  it('shows the summary per role and marks accounts without a factor and admins without a passkey', () => {
    const { el } = create();
    expect(el.querySelector('[data-summary="r1"]')?.textContent).toContain('4');
    expect(el.querySelector('[data-user="u2"] [data-none]')).not.toBeNull();
    expect(el.querySelector('[data-user="u1"] [data-phishing]')).not.toBeNull();
    expect(el.querySelector('[data-user="u1"] [data-none]')).toBeNull();
  });

  it('filters by role and to accounts with no second factor', () => {
    const { cmp, mfaCoverage } = create();
    cmp.onRole({ target: { value: 'r1' } } as unknown as Event);
    expect(mfaCoverage).toHaveBeenLastCalledWith({ roleId: 'r1', missingOnly: false });
    cmp.onMissingOnly({ target: { checked: true } } as unknown as Event);
    expect(mfaCoverage).toHaveBeenLastCalledWith({ roleId: 'r1', missingOnly: true });
  });
});
