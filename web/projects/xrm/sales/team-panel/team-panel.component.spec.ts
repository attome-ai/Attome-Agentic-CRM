import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { xrmAr } from '@attome/xrm/core/i18n-ar';
import { xrmEn } from '@attome/xrm/core/i18n-en';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SalesApiService } from '../sales-api.service';
import { SalesTeamApiService } from '../team-api';
import { TeamPanelComponent } from './team-panel.component';

const OPP = '01900000-0000-7000-8000-0000000000e2';

function at(catalog: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>(
    (node, part) => (node && typeof node === 'object' ? (node as Record<string, unknown>)[part] : undefined),
    catalog,
  );
}

describe('TeamPanelComponent (D7-T7)', () => {
  let team: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    team = {
      members: vi.fn(() => of([
        { id: 'm1', user_ref: 'u1', partner_contact_ref: null, team_role_ref: 'r1', access_level: 'edit' },
      ])),
      roles: vi.fn(() => of([{ id: 'r1', label: 'Sales engineer' }])),
      users: vi.fn(() => of([{ id: 'u1', label: 'Sara' }, { id: 'u2', label: 'Omar' }])),
      addMember: vi.fn(() => of({})),
      removeMember: vi.fn(() => of(undefined)),
      copyAccountTeam: vi.fn(() => of({ added: 1, skipped: 0 })),
    };
    TestBed.configureTestingModule({
      imports: [TeamPanelComponent],
      providers: [
        { provide: SalesTeamApiService, useValue: team },
        { provide: SalesApiService, useValue: { featureOn: vi.fn(() => of(true)) } },
        {
          provide: LangService,
          useValue: { intlLocale: () => 'ar', translate: (k: string) => String(at(xrmAr, k) ?? k), errorText: () => '' },
        },
      ],
    });
  });

  it('arabic labels', () => {
    const en = at(xrmEn, 'xrm.sales.team') as Record<string, string>;
    const ar = at(xrmAr, 'xrm.sales.team') as Record<string, string>;
    expect(Object.keys(ar).sort()).toEqual(Object.keys(en).sort());
    expect(Object.keys(at(xrmAr, 'xrm.sales.splits') as object).sort())
      .toEqual(Object.keys(at(xrmEn, 'xrm.sales.splits') as object).sort());

    const fixture = TestBed.createComponent(TeamPanelComponent);
    fixture.componentRef.setInput('recordId', OPP);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('.tp-title')?.textContent?.trim()).toBe(ar['title']);
    expect(el.textContent).toContain('Sara');
    expect(el.textContent).toContain(ar['accessEdit']);
  });
});
