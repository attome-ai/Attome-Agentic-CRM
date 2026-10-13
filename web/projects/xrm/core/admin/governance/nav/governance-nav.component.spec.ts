import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { LangService } from '@attome/base';
import { GovernanceNavComponent } from './governance-nav.component';

describe('GovernanceNavComponent', () => {
  it('links the four governance screens under /xrm/admin', async () => {
    await TestBed.configureTestingModule({
      imports: [GovernanceNavComponent],
      providers: [
        provideRouter([]),
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(GovernanceNavComponent);
    fixture.detectChanges();
    const hrefs = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('a'))
      .map(a => a.getAttribute('href'));
    expect(hrefs).toEqual([
      '/xrm/admin/data/quality',
      '/xrm/admin/data/catalog',
      '/xrm/admin/changes',
      '/xrm/admin/state-models',
    ]);
  });
});
