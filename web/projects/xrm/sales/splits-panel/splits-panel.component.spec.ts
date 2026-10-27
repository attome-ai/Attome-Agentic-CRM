import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SalesApiService } from '../sales-api.service';
import { SalesTeamApiService } from '../team-api';
import type { SplitRow, SplitType } from '../team-api';
import { SplitsPanelComponent, typeTotals, unbalancedTypes } from './splits-panel.component';

const OPP = '01900000-0000-7000-8000-0000000000e1';
const REVENUE: SplitType = { id: 't-rev', name: 'Revenue', must_total_100: true };
const OVERLAY: SplitType = { id: 't-ovl', name: 'Overlay', must_total_100: false };

function split(member: string, type: string, percent: string, extra: Partial<SplitRow> = {}): SplitRow {
  return { id: `s-${member}-${type}`, member_ref: member, split_type_ref: type, line_ref: null, percent, ...extra };
}

describe('SplitsPanelComponent (D7-T7)', () => {
  let team: Record<string, ReturnType<typeof vi.fn>>;
  let rows: SplitRow[];

  beforeEach(() => {
    rows = [split('m1', 't-rev', '70'), split('m2', 't-rev', '30'), split('m2', 't-ovl', '20')];
    team = {
      splits: vi.fn(() => of(rows)),
      splitTypes: vi.fn(() => of([REVENUE, OVERLAY])),
      members: vi.fn(() => of([
        { id: 'm1', user_ref: 'u1', partner_contact_ref: null, team_role_ref: null, access_level: 'edit' },
        { id: 'm2', user_ref: 'u2', partner_contact_ref: null, team_role_ref: null, access_level: 'read' },
      ])),
      users: vi.fn(() => of([{ id: 'u1', label: 'Owner' }, { id: 'u2', label: 'Engineer' }])),
      saveSplits: vi.fn(() => of({ opportunity_id: OPP, splits: [], approval_request_id: null })),
    };
    TestBed.configureTestingModule({
      imports: [SplitsPanelComponent],
      providers: [
        { provide: SalesTeamApiService, useValue: team },
        {
          provide: SalesApiService,
          useValue: {
            featureOn: vi.fn(() => of(true)),
            opportunity: vi.fn(() => of({ row_version: 1, data: { stage: 'proposal' } })),
          },
        },
        {
          provide: LangService,
          useValue: { intlLocale: () => 'en-US', translate: (k: string) => k, errorText: (e: { message: string }) => e.message },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(SplitsPanelComponent);
    fixture.componentRef.setInput('recordId', OPP);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    return { fixture, el };
  }

  it('revenue total must be 100', () => {
    expect(unbalancedTypes(rows, [REVENUE, OVERLAY])).toEqual([]);
    const short = [split('m1', 't-rev', '70'), split('m2', 't-rev', '20'), split('m2', 't-ovl', '20')];
    expect(typeTotals(short).get('t-rev|')).toBe(90);
    expect(unbalancedTypes(short, [REVENUE, OVERLAY])).toEqual(['t-rev']);

    rows = short;
    const { fixture, el } = render();
    (el.querySelector('[data-testid="splits-panel-save"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(team['saveSplits']).not.toHaveBeenCalled();
    expect(el.querySelector('[data-testid="splits-panel-error"]')?.textContent).toContain('xrm.sales.splits.mustTotal');
  });

  it('amount hidden without grant', () => {
    const { el } = render();
    expect(el.querySelector('[data-testid="splits-panel-amount"]')).toBeNull();

    rows = rows.map(r => ({ ...r, amount: '1000.00' }));
    const second = render();
    expect(second.el.querySelector('[data-testid="splits-panel-amount"]')).not.toBeNull();
  });
});
