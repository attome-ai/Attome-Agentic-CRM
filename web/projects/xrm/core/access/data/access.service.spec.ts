import { signal, WritableSignal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, AuthService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AccessService } from './access.service';

describe('AccessService (NGB-1.2)', () => {
  let userId: WritableSignal<string | null>;
  let get: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    userId = signal<string | null>('u1');
    get = vi.fn(() => of({ is_admin: false, privileges: ['dashboard.update'] }));
    TestBed.configureTestingModule({
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: AuthService, useValue: { userId } },
      ],
    });
  });

  const svc = () => TestBed.inject(AccessService);

  it('holds no privilege before ready() emits', () => {
    expect(svc().hasPrivilege('dashboard.update')).toBe(false);
  });

  it('shares one whoami per user and resolves the privilege', () => {
    const s = svc();
    s.ready().subscribe();
    s.ready().subscribe();
    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith('/api/v1/admin/security/whoami');
    expect(s.hasPrivilege('dashboard.update')).toBe(true);
    expect(s.hasPrivilege('system.admin')).toBe(false);
  });

  it('an admin holds every privilege', () => {
    get.mockReturnValue(of({ is_admin: true, privileges: [] }));
    const s = svc();
    s.ready().subscribe();
    expect(s.hasPrivilege('system.admin')).toBe(true);
  });

  it('does not carry one user\'s privileges to the next user in the tab', () => {
    const s = svc();
    s.ready().subscribe();
    expect(s.hasPrivilege('dashboard.update')).toBe(true);

    userId.set('u2');
    expect(s.hasPrivilege('dashboard.update')).toBe(false);

    get.mockReturnValue(of({ is_admin: false, privileges: [] }));
    s.ready().subscribe();
    expect(get).toHaveBeenCalledTimes(2);
    expect(s.hasPrivilege('dashboard.update')).toBe(false);
  });

  it('fails closed when whoami fails', () => {
    get.mockReturnValue(throwError(() => ({ kind: 'forbidden' })));
    const s = svc();
    s.ready().subscribe();
    expect(s.hasPrivilege('dashboard.update')).toBe(false);
  });

  it('exposes the role ids whoami returns (D-789 §5)', () => {
    get.mockReturnValue(of({ is_admin: false, privileges: [], role_ids: ['r1', 'r2'] }));
    const s = svc();
    expect(s.roleIds()).toEqual([]);
    s.ready().subscribe();
    expect(s.roleIds()).toEqual(['r1', 'r2']);
    userId.set('u2');
    expect(s.roleIds()).toEqual([]);
  });

  it('holds no role when whoami omits role_ids or fails', () => {
    const s = svc();
    s.ready().subscribe();
    expect(s.roleIds()).toEqual([]);
    userId.set('u3');
    get.mockReturnValue(throwError(() => ({ kind: 'forbidden' })));
    s.ready().subscribe();
    expect(s.roleIds()).toEqual([]);
  });

  it('makes no request while signed out', () => {
    userId.set(null);
    svc().ready().subscribe();
    expect(get).not.toHaveBeenCalled();
  });
});
