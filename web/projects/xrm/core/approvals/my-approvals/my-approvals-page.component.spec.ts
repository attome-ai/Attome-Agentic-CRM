import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService, UserPreferencesService } from '@attome/base';
import type { ApiError } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MyApprovalsService, MyWorkItem } from '../services/my-approvals.service';
import { MyApprovalsPageComponent } from './my-approvals-page.component';

function item(id: string, title = `Approve: ${id}`): MyWorkItem {
  return {
    record_id: id, title, provider: 'approvals', source_entity: 'approval_request', state: 'pending',
    due_date: '2026-09-30T12:00:00Z', priority: null, row_version: 2,
    actions: [
      { key: 'approve', method: 'POST', route: `/api/v1/approvals/${id}/decide` },
      { key: 'reject', method: 'POST', route: `/api/v1/approvals/${id}/decide` },
    ],
  };
}

describe('MyApprovalsPageComponent', () => {
  let svc: { list: ReturnType<typeof vi.fn>; decide: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    svc = { list: vi.fn(), decide: vi.fn() };
    TestBed.configureTestingModule({
      imports: [MyApprovalsPageComponent],
      providers: [
        { provide: MyApprovalsService, useValue: svc },
        {
          provide: LangService,
          useValue: {
            intlLocale: () => 'en-US',
            translate: (key: string, params?: Record<string, unknown>) =>
              params ? `${key} ${JSON.stringify(params)}` : key,
          },
        },
        { provide: UserPreferencesService, useValue: { timezone: signal<string | null>('UTC') } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(MyApprovalsPageComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const q = (testId: string) => el.querySelector<HTMLElement>(`[data-testid="${testId}"]`);
    const qa = (testId: string) => Array.from(el.querySelectorAll<HTMLElement>(`[data-testid="${testId}"]`));
    return { fixture, el, q, qa };
  }

  it('shows the empty state when nothing is pending', () => {
    svc.list.mockReturnValue(of({ items: [] }));
    const { q } = render();
    expect(q('my-approvals-empty')?.textContent).toContain('myApprovals.empty');
  });

  it('surfaces a load failure as an alert', () => {
    const err: ApiError = { kind: 'internal', status: 500, message: 'Internal server error' };
    svc.list.mockReturnValue(throwError(() => err));
    const { q } = render();
    expect(q('my-approvals-load-error')?.getAttribute('role')).toBe('alert');
    expect(q('my-approvals-load-error')?.textContent).toContain('Internal server error');
  });

  it('approves an item through its own action, removes it and announces it', () => {
    svc.list.mockReturnValue(of({ items: [item('a'), item('b')] }));
    svc.decide.mockReturnValue(of({ id: 'a', status: 'approved' }));
    const { fixture, q, qa } = render();
    expect(qa('my-approvals-item').length).toBe(2);
    qa('my-approvals-approve')[0].click();
    fixture.detectChanges();
    expect(svc.decide).toHaveBeenCalledWith(item('a').actions[0], 'approve', 2, undefined);
    expect(qa('my-approvals-item').length).toBe(1);
    expect(q('my-approvals-notice')?.getAttribute('role')).toBe('status');
    expect(q('my-approvals-notice')?.textContent).toContain('myApprovals.approved');
  });

  it('rejects with the reject action', () => {
    svc.list.mockReturnValue(of({ items: [item('a')] }));
    svc.decide.mockReturnValue(of({ id: 'a', status: 'rejected' }));
    const { fixture, q, qa } = render();
    qa('my-approvals-reject')[0].click();
    fixture.detectChanges();
    expect(svc.decide).toHaveBeenCalledWith(item('a').actions[1], 'reject', 2, undefined);
    expect(q('my-approvals-notice')?.textContent).toContain('myApprovals.rejected');
  });

  it('keeps the item and shows a 403 or 409 on it rather than swallowing it', () => {
    svc.list.mockReturnValue(of({ items: [item('a')] }));
    const forbidden: ApiError = { kind: 'forbidden', status: 403, message: 'Forbidden' };
    const conflict: ApiError = { kind: 'version_conflict', status: 409, message: 'stale' };
    svc.decide.mockReturnValueOnce(throwError(() => forbidden)).mockReturnValueOnce(throwError(() => conflict));
    const { fixture, q, qa } = render();
    qa('my-approvals-approve')[0].click();
    fixture.detectChanges();
    expect(qa('my-approvals-item').length).toBe(1);
    expect(q('my-approvals-item-error')?.getAttribute('role')).toBe('alert');
    expect(q('my-approvals-item-error')?.textContent).toContain('myApprovals.error.forbidden');
    qa('my-approvals-approve')[0].click();
    fixture.detectChanges();
    expect(q('my-approvals-item-error')?.textContent).toContain('myApprovals.error.conflict');
  });

  it('sends the item\'s comment with the decision', () => {
    svc.list.mockReturnValue(of({ items: [item('a')] }));
    svc.decide.mockReturnValue(of({ id: 'a', status: 'rejected' }));
    const { fixture, q, qa } = render();
    const box = q('my-approvals-comment') as HTMLTextAreaElement;
    expect(box.getAttribute('maxlength')).toBe('2000');
    box.value = 'missing the cost centre';
    box.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    qa('my-approvals-reject')[0].click();
    fixture.detectChanges();
    expect(svc.decide).toHaveBeenCalledWith(item('a').actions[1], 'reject', 2, 'missing the cost centre');
  });

  it('offers no decision for an item without a row_version', () => {
    const unversioned = { ...item('a'), row_version: undefined };
    svc.list.mockReturnValue(of({ items: [unversioned] }));
    const { qa } = render();
    expect(qa('my-approvals-approve').length).toBe(0);
    expect(qa('my-approvals-comment').length).toBe(0);
  });

  it('offers only the actions the provider returned', () => {
    const onlyApprove = { ...item('a'), actions: [item('a').actions[0]] };
    svc.list.mockReturnValue(of({ items: [onlyApprove] }));
    const { qa } = render();
    expect(qa('my-approvals-approve').length).toBe(1);
    expect(qa('my-approvals-reject').length).toBe(0);
  });

  it('loads the next page when the server returns a cursor', () => {
    svc.list.mockReturnValueOnce(of({ items: [item('a')], next_cursor: 'c1' }))
      .mockReturnValueOnce(of({ items: [item('b')], next_cursor: null }));
    const { fixture, q, qa } = render();
    q('my-approvals-more')!.click();
    fixture.detectChanges();
    expect(svc.list).toHaveBeenLastCalledWith('c1');
    expect(qa('my-approvals-item').length).toBe(2);
    expect(q('my-approvals-more')).toBeNull();
  });
});
