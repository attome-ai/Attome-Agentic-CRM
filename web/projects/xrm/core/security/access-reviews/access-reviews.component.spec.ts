import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AccessReviewsComponent } from './access-reviews.component';
import { AccessReviewCampaign, AccessReviewItem, AccessReviewsService, evidenceCsv } from './access-reviews.service';

const CAMPAIGN: AccessReviewCampaign = {
  id: 'c1',
  name: 'Q4 roles',
  scope: 'role',
  due_date: '2026-12-31T00:00:00Z',
  status: 'active',
  item_count: 2,
  decided_count: 0,
  created_at: '2026-10-01T00:00:00Z',
};

const ITEMS: AccessReviewItem[] = [
  { id: 'i1', approval_request_id: 'a1', subject_user_id: 'u1', grant_id: 'g1', reviewer_user_id: 'me' },
  { id: 'i2', approval_request_id: 'a2', subject_user_id: 'u2', grant_id: 'g2', reviewer_user_id: 'someone-else' },
];

describe('AccessReviewsComponent', () => {
  let service: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    service = {
      listCampaigns: vi.fn().mockReturnValue(of([CAMPAIGN])),
      listItems: vi.fn().mockReturnValue(of(ITEMS)),
      decide: vi.fn().mockReturnValue(
        of({ ...ITEMS[0], decision: 'revoke', decision_reason: 'left the team', decided_by: 'me' }),
      ),
    };
    TestBed.configureTestingModule({
      imports: [AccessReviewsComponent],
      providers: [
        { provide: AccessReviewsService, useValue: service },
        { provide: AuthService, useValue: { userId: signal('me') } },
        { provide: LangService, useValue: { translate: (k: string) => k, intlLocale: () => 'en' } },
      ],
    });
    TestBed.overrideComponent(AccessReviewsComponent, { set: { template: '' } });
  });

  function create(): AccessReviewsComponent {
    const fixture = TestBed.createComponent(AccessReviewsComponent);
    fixture.detectChanges();
    return fixture.componentInstance;
  }

  it('lists campaigns and shows only my accesses when asked', () => {
    const c = create();
    expect(c.campaigns()).toEqual([CAMPAIGN]);
    c.open(CAMPAIGN);
    expect(c.shown().length).toBe(2);
    c.mineOnly.set(true);
    expect(c.shown().map(i => i.id)).toEqual(['i1']);
    expect(c.undecided()).toBe(1);
  });

  it('sends the reason with a decision and records the answer', () => {
    const c = create();
    c.open(CAMPAIGN);
    c.setReason('i1', '  left the team ');
    c.decide(c.items()[0], 'revoke');
    expect(service['decide']).toHaveBeenCalledWith('c1', 'i1', 'revoke', '  left the team ');
    expect(c.items()[0].decision).toBe('revoke');
    expect(c.items()[0].decision_reason).toBe('left the team');
    expect(c.campaigns()[0].decided_count).toBe(1);
    // A decided access is not decided again.
    c.decide(c.items()[0], 'keep');
    expect(service['decide']).toHaveBeenCalledTimes(1);
  });

  it('writes evidence as CSV, quoting what needs it', () => {
    const csv = evidenceCsv(CAMPAIGN, [
      { ...ITEMS[0], decision: 'keep', decision_reason: 'still on "billing", needed' },
    ]);
    const [header, row] = csv.trimEnd().split('\r\n');
    expect(header.startsWith('campaign,campaign_id,scope')).toBe(true);
    expect(row).toContain('"still on ""billing"", needed"');
    expect(row.startsWith('Q4 roles,c1,role,')).toBe(true);
  });
});
