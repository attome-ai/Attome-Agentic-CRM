import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { UsageComponent } from './usage.component';

describe('UsageComponent (U11-T1)', () => {
  it('shows users, the contract reference and the modules on', () => {
    const get = vi.fn().mockReturnValue(of({
      modules_on: ['core', 'workflow'],
      users_active: 12,
      users_signed_in_30d: 9,
      contract_reference: null,
    }));
    TestBed.configureTestingModule({
      imports: [UsageComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(UsageComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(get).toHaveBeenCalledWith('/api/v1/admin/usage');
    expect(el.querySelector('[data-figure="active"]')?.textContent).toContain('12');
    expect(el.querySelector('[data-figure="recent"]')?.textContent).toContain('9');
    expect(el.textContent).toContain('usagePage.noContract');
    expect(el.querySelectorAll('.us-modules li').length).toBe(2);
  });
});
