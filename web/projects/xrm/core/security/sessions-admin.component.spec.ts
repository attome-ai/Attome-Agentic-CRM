import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { ConfirmService } from '@attome/base/dialog';

import { SecurityAdminService } from './security-admin.service';
import { SessionsAdminComponent } from './sessions-admin.component';

describe('SessionsAdminComponent', () => {
  let fixture: ComponentFixture<SessionsAdminComponent>;
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  const session = (id: string) => ({
    id,
    user_id: 'u-' + id,
    user_email: id + '@example.test',
    device_label: 'chrome/windows',
    user_agent: 'Mozilla/5.0',
    sign_in_method: 'password',
    client_kind: 'web',
    created_at: '2026-10-29T08:00:00Z',
    last_activity_at: null,
  });
  const page = (ids: string[]) => of({ items: ids.map(session), total: ids.length, page: 1, page_size: 50 });

  const el = () => fixture.nativeElement as HTMLElement;

  async function render() {
    await TestBed.configureTestingModule({
      imports: [SessionsAdminComponent],
      providers: [
        { provide: SecurityAdminService, useValue: svc },
        { provide: ConfirmService, useValue: { confirm: vi.fn().mockResolvedValue(true) } },
        {
          provide: LangService,
          useValue: {
            translate: (key: string, params?: Record<string, unknown>) => (params ? `${key}:${JSON.stringify(params)}` : key),
            errorText: () => 'error',
            intlLocale: () => 'en-US',
          },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(SessionsAdminComponent);
    fixture.detectChanges();
  }

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      listRoles: vi.fn().mockReturnValue(of([{ id: 'r1', name: 'Sales' }])),
      listSessions: vi.fn().mockReturnValue(page(['a', 'b'])),
      listUserSessions: vi.fn().mockReturnValue(page(['a'])),
      endSession: vi.fn().mockReturnValue(of(undefined)),
      revokeUserSessions: vi.fn().mockReturnValue(of({ ended_users: 1, queued: false })),
      revokeRoleSessions: vi.fn().mockReturnValue(of({ ended_users: 0, queued: true })),
    };
  });

  it('lists every live session on the first page', async () => {
    await render();
    expect(svc['listSessions']).toHaveBeenCalledWith(undefined, 1, 50);
    expect(el().querySelectorAll('tbody tr').length).toBe(2);
    expect(el().textContent).toContain('a@example.test');
  });

  it('narrows to a role and ends every session of its holders', async () => {
    await render();
    const select = el().querySelector('[data-testid="sessions-role"]') as HTMLSelectElement;
    select.value = 'r1';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(svc['listSessions']).toHaveBeenLastCalledWith('r1', 1, 50);
    await fixture.componentInstance.endAllOfRole();
    fixture.detectChanges();
    expect(svc['revokeRoleSessions']).toHaveBeenCalledWith('r1');
    expect(el().querySelector('[data-notice]')?.textContent).toContain('sessionsAdmin.queued');
  });

  it('shows one person and ends one session or all of theirs', async () => {
    await render();
    const input = el().querySelector('[data-testid="sessions-user"]') as HTMLInputElement;
    input.value = 'u-a';
    input.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(svc['listUserSessions']).toHaveBeenCalledWith('u-a', 1, 50);
    (el().querySelector('tbody tr button') as HTMLButtonElement).click();
    expect(svc['endSession']).toHaveBeenCalledWith('a');
    fixture.detectChanges();
    (el().querySelector('[data-testid="end-user"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(svc['revokeUserSessions']).toHaveBeenCalledWith('u-a');
    expect(el().querySelector('[data-notice]')?.textContent).toContain('sessionsAdmin.ended');
  });
});
