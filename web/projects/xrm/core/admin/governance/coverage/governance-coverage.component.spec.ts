import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { SdkService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { Coverage, GovernanceCoverageComponent, Scorecard } from './governance-coverage.component';
import { sdkFromApi } from '../../../../testing/sdk-from-api';

const COVERAGE: Coverage = {
  entities_without_domain: ['lead'],
  domains_without_owner: [{ id: 'd1', name: 'Customers' }],
  personal_attributes_without_policy: [{ entity: 'contact', attribute: 'phone', classification: 'personal' }],
  policies_without_enforcement: [],
  stewards_with_overdue_items: [],
  truncated: false,
};

const CARD: Scorecard = {
  domain: { id: 'd1', name: 'Customers' },
  quality: [{ entity: 'contact', dimension: 'completeness', score: 92, computed_at: '2026-10-30T00:00:00Z' }],
  quality_average: 92,
  open_items: 3,
  overdue_items: 1,
  open_exceptions: 0,
  policies: 2,
  enforced_policies: 1,
};

describe('GovernanceCoverageComponent (L3-T7)', () => {
  it('shows the gaps and opens a domain scorecard', () => {
    const get = vi.fn((path: string) => of(path.endsWith('/scorecard') ? CARD : COVERAGE));
    TestBed.configureTestingModule({
      imports: [GovernanceCoverageComponent],
      providers: [
        provideRouter([]),
        { provide: SdkService, useValue: sdkFromApi({ get }) },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('ar'), intlLocale: () => 'ar-SA' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(GovernanceCoverageComponent);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(get).toHaveBeenCalledWith('/api/v1/admin/governance/coverage');
    const unowned = el.querySelector('[data-testid="gc-unowned"]') as HTMLElement;
    expect(unowned.textContent).toContain('Customers');
    expect(el.textContent).toContain('lead');
    expect(el.textContent).toContain('contact.phone');

    (unowned.querySelector('button') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(get).toHaveBeenCalledWith('/api/v1/admin/governance/domains/d1/scorecard');
    const card = el.querySelector('[data-testid="gc-scorecard"]') as HTMLElement;
    expect(card.textContent).toContain('governance.coverage.items');
  });
});
