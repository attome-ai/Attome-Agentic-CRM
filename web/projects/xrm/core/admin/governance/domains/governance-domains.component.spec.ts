import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { SdkService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { GovernanceDomain, GovernanceDomainsComponent, domainTree } from './governance-domains.component';
import { sdkFromApi } from '../../../../testing/sdk-from-api';

const DOMAINS: GovernanceDomain[] = [
  { id: 'c', name: 'Customers' },
  { id: 'k', name: 'KYC', parent_ref: 'c' },
  { id: 'a', name: 'Accounts', parent_ref: 'c' },
  { id: 'f', name: 'Finance' },
  { id: 'x', name: 'Orphan', parent_ref: 'gone' },
];

describe('domainTree (L3-T7)', () => {
  it('nests sub-domains under their parent, by name, and roots an unknown parent', () => {
    expect(domainTree(DOMAINS).map(r => `${r.depth}:${r.domain.name}`)).toEqual([
      '0:Customers', '1:Accounts', '1:KYC', '0:Finance', '0:Orphan',
    ]);
  });

  it('survives a parent loop', () => {
    const loop: GovernanceDomain[] = [{ id: 'p', name: 'P', parent_ref: 'q' }, { id: 'q', name: 'Q', parent_ref: 'p' }];
    expect(domainTree(loop).length).toBe(2);
  });
});

describe('GovernanceDomainsComponent (L3-T7)', () => {
  it('shows a domain roles and its policies, enforced or not, in Arabic', () => {
    const getAllPages = vi.fn((path: string, _params?: unknown) => {
      if (path.endsWith('/roles')) return of([{ user_id: 'u1', role: 'steward' }]);
      if (path.endsWith('/policies')) {
        return of([
          { id: 'p1', name_en: 'Retention', name_ar: 'الاحتفاظ', version: 1, enforcements: [{ kind: 'retention', target_ref: 'contact' }] },
          { id: 'p2', name_en: 'Masking', name_ar: null, version: 1, enforcements: [] },
        ]);
      }
      return of(DOMAINS);
    });
    TestBed.configureTestingModule({
      imports: [GovernanceDomainsComponent],
      providers: [
        provideRouter([]),
        { provide: SdkService, useValue: sdkFromApi({ getAllPages }) },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('ar'), intlLocale: () => 'ar-SA' } },
      ],
    });
    const fixture = TestBed.createComponent(GovernanceDomainsComponent);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const buttons = el.querySelectorAll('[data-testid="gd-tree"] button');
    expect(buttons.length).toBe(5);
    (buttons[0] as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(getAllPages).toHaveBeenCalledWith('/api/v1/admin/governance/domains/c/roles');
    expect(getAllPages).toHaveBeenCalledWith('/api/v1/admin/governance/policies', { domain: 'c' });
    const policies = el.querySelectorAll('[data-testid="gd-policies"] li');
    expect(policies.length).toBe(2);
    expect(policies[0].textContent).toContain('الاحتفاظ');
    expect(policies[0].textContent).toContain('governance.domains.enforced');
    expect(policies[1].textContent).toContain('governance.domains.notEnforced');
  });
});
