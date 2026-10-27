import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ImpersonationAccessPageComponent } from './impersonation-access-page.component';

describe('ImpersonationAccessPageComponent', () => {
  let api: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    api = {
      getAllPages: vi.fn((path: string) => of(path.endsWith('sessions')
        ? [{ id: 's1', actor_id: 'a1', mode: 'view', reason: 'ticket', started_at: '2026-10-27T00:00:00Z', expires_at: '2026-10-27T00:30:00Z' }]
        : [])),
      post: vi.fn(() => of({ id: 'c1', actor_id: 'a1', granted_at: '2026-10-27T00:00:00Z', expires_at: '2026-10-27T04:00:00Z' })),
      delete: vi.fn(() => of(undefined)),
    };
    TestBed.configureTestingModule({
      imports: [ImpersonationAccessPageComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { translate: (k: string) => k, errorText: (e: { message: string }) => e.message, intlLocale: () => 'en' } },
      ],
    });
    TestBed.overrideComponent(ImpersonationAccessPageComponent, { set: { template: '' } });
  });

  function create(): ImpersonationAccessPageComponent {
    const fixture = TestBed.createComponent(ImpersonationAccessPageComponent);
    fixture.detectChanges();
    return fixture.componentInstance;
  }

  it('lists the sessions about me', () => {
    expect(create().sessions().map(s => s.id)).toEqual(['s1']);
  });

  it('allows an administrator by email for a number of hours, and withdraws it', () => {
    const c = create();
    c.email = ' admin@example.com ';
    c.hours = 6;
    c.grant();
    expect(api['post']).toHaveBeenCalledWith('/api/v1/me/impersonation-consents', { actor_email: 'admin@example.com', hours: 6 });
    expect(c.consents()[0].id).toBe('c1');
    c.withdraw(c.consents()[0]);
    expect(api['delete']).toHaveBeenCalledWith('/api/v1/me/impersonation-consents/c1');
    expect(c.consents()[0].revoked_at).toBeTruthy();
  });

  it('asks for the email first', () => {
    const c = create();
    c.grant();
    expect(api['post']).not.toHaveBeenCalled();
    expect(c.error()).toBe('impersonationAccess.emailRequired');
  });
});
