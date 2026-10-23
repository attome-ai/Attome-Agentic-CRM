import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap } from '@angular/router';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ApprovalDetail, ApprovalRequestPageComponent, showValue } from './request-page.component';

const DETAIL: ApprovalDetail = {
  id: 'r-1',
  action_type: 'approval_process.change',
  title: 'Discount above 20%',
  status: 'pending',
  step: 0,
  step_count: 2,
  requested_by: 'u-1',
  requested_by_name: 'sara',
  requested_at: '2026-10-23T09:00:00Z',
  expires_at: '2026-10-30T09:00:00Z',
  executed_at: null,
  row_version: 3,
  reason: 'Strategic customer, three-year deal',
  regarding_entity: 'opportunity',
  regarding_id: 'o-1',
  changes: [{ attribute: 'discount', from: '15', to: 25 }],
  payload: {},
  can_decide: true,
  decisions: [{
    approver_id: 'u-2', approver_name: 'omar', decided_by: null, step: 0,
    decision: 'approved', comment: 'fine by sales', decided_at: '2026-10-23T10:00:00Z',
  }],
};

describe('ApprovalRequestPageComponent (M9-T4)', () => {
  function create(detail: ApprovalDetail = DETAIL) {
    const get = vi.fn((_url: string) => of(detail));
    const post = vi.fn((_url: string, _body: unknown) => of({}));
    TestBed.configureTestingModule({
      imports: [ApprovalRequestPageComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: ActivatedRoute, useValue: { snapshot: { paramMap: convertToParamMap({ id: 'r-1' }) } } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(ApprovalRequestPageComponent);
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('shows what is asked, by whom and why', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/approvals/r-1');
    const text: string = fixture.nativeElement.textContent;
    expect(text).toContain('Discount above 20%');
    expect(text).toContain('sara');
    expect(text).toContain('Strategic customer, three-year deal');
  });

  it('shows each change as from and to', () => {
    const { fixture } = create();
    const row: HTMLElement | null = fixture.nativeElement.querySelector('[data-attribute="discount"]');
    expect(row?.querySelector('.rq-from')?.textContent?.trim()).toBe('15');
    expect(row?.querySelector('.rq-to')?.textContent?.trim()).toBe('25');
  });

  it('lists the decisions so far with their comments', () => {
    const { fixture } = create();
    const decision: HTMLElement | null = fixture.nativeElement.querySelector('[data-decision="approved"]');
    expect(decision?.textContent).toContain('approvalRequest.decision.approved');
    expect(decision?.textContent).toContain('fine by sales');
  });

  it('decides with the row version and a trimmed comment', () => {
    const { fixture, post } = create();
    const component = fixture.componentInstance;
    component.comment = '  ok  ';
    component.decide('approve');
    expect(post).toHaveBeenCalledWith('/api/v1/approvals/r-1/decide', {
      decision: 'approve', row_version: 3, comment: 'ok',
    });
  });

  it('offers no decision to someone who may not decide', () => {
    const { fixture } = create({ ...DETAIL, can_decide: false });
    expect(fixture.nativeElement.querySelector('.rq-approve')).toBeNull();
  });

  it('shows values plainly', () => {
    expect(showValue(null)).toBe('—');
    expect(showValue('a')).toBe('a');
    expect(showValue(25)).toBe('25');
    expect(showValue({ a: 1 })).toBe('{"a":1}');
  });
});
