import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router } from '@angular/router';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ApprovalLinkPageComponent, ApprovalLinkView } from './approval-link-page.component';

const VIEW: ApprovalLinkView = {
  request_id: 'r-1', action_type: 'approval_process', title: 'Large discount', status: 'pending',
  requested_by_name: 'sara', requested_at: '2026-10-23T09:00:00Z', reason: 'three-year deal',
  changes: [], decide_here: true, link_expires_at: '2026-10-26T09:00:00Z',
};

describe('ApprovalLinkPageComponent (M9-T3)', () => {
  function create(view: ApprovalLinkView = VIEW, fragment: string | null = 'pid.secret') {
    const post = vi.fn((url: string, _body: unknown) =>
      of(url.endsWith('/decide') ? { request_id: 'r-1', status: 'approved' } : view));
    const navigate = vi.fn(() => Promise.resolve(true));
    TestBed.configureTestingModule({
      imports: [ApprovalLinkPageComponent],
      providers: [
        { provide: ApiService, useValue: { post } },
        { provide: Router, useValue: { navigate } },
        { provide: ActivatedRoute, useValue: { snapshot: { fragment } } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(ApprovalLinkPageComponent);
    fixture.detectChanges();
    return { fixture, post, navigate };
  }

  it('reads the request with the token from the fragment', () => {
    const { fixture, post } = create();
    expect(post).toHaveBeenCalledWith('/api/v1/approvals/email-link', { token: 'pid.secret' });
    expect(fixture.nativeElement.textContent).toContain('Large discount');
    expect(fixture.nativeElement.textContent).toContain('three-year deal');
  });

  it('decides a low-risk request on the page', () => {
    const { fixture, post } = create();
    fixture.componentInstance.decide('approve');
    expect(post).toHaveBeenCalledWith('/api/v1/approvals/email-link/decide', { token: 'pid.secret', decision: 'approve' });
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('approvalLink.done.approved');
  });

  it('sends a high-risk request to the signed-in request page', () => {
    const { fixture, navigate } = create({ ...VIEW, decide_here: false });
    expect(fixture.nativeElement.querySelector('.al-approve')).toBeNull();
    (fixture.nativeElement.querySelector('.al-open') as HTMLButtonElement).click();
    expect(navigate).toHaveBeenCalledWith(['/xrm/approvals/requests', 'r-1']);
  });

  it('asks nothing of the server without a token', () => {
    const { fixture, post } = create(VIEW, null);
    expect(post).not.toHaveBeenCalled();
    expect(fixture.nativeElement.textContent).toContain('approvalLink.invalid');
  });
});
