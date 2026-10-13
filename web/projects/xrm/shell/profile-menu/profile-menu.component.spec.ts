import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiError, AuthService, LangService, ThemeService } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { EntityService } from '@attome/xrm/core/entity';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ProfileMenuComponent } from './profile-menu.component';

describe('ProfileMenuComponent sign-out', () => {
  let logout: ReturnType<typeof vi.fn>;
  let confirm: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    logout = vi.fn();
    confirm = vi.fn();
    TestBed.configureTestingModule({
      imports: [ProfileMenuComponent],
      providers: [
        provideRouter([]),
        { provide: AuthService, useValue: { userId: signal<string | null>(null), logout } },
        { provide: EntityService, useValue: { get: () => of({ data: {} }) } },
        { provide: DialogService, useValue: { confirm } },
        { provide: ThemeService, useValue: { mode: signal('light'), setMode: vi.fn() } },
        { provide: LangService, useValue: { current: signal('en'), set: vi.fn(), translate: (key: string) => key } },
      ],
    });
  });

  const mount = () => {
    const fixture = TestBed.createComponent(ProfileMenuComponent);
    fixture.detectChanges();
    return fixture.componentInstance;
  };
  const failure: ApiError = { status: 500, kind: 'internal', message: '' };
  const flush = () => new Promise(resolve => setTimeout(resolve));

  it('asks nothing when sign-out succeeds', () => {
    logout.mockReturnValue(of(undefined));
    mount().logout();
    expect(confirm).not.toHaveBeenCalled();
  });

  it('NGB-F1 a failed sign-out is surfaced', async () => {
    logout.mockReturnValue(throwError(() => failure));
    confirm.mockResolvedValue(false);

    mount().logout();
    await flush();

    expect(confirm).toHaveBeenCalledTimes(1);
    expect(confirm).toHaveBeenCalledWith(expect.objectContaining({
      title: 'shell.signOutFailedTitle',
      message: 'shell.signOutFailed',
      confirmText: 'shell.signOutRetry',
    }));
    expect(logout).toHaveBeenCalledTimes(1);
  });

  it('retries the sign-out when the user asks to', async () => {
    logout.mockReturnValueOnce(throwError(() => failure)).mockReturnValueOnce(of(undefined));
    confirm.mockResolvedValue(true);

    mount().logout();
    await flush();

    expect(logout).toHaveBeenCalledTimes(2);
    expect(confirm).toHaveBeenCalledTimes(1);
  });
});
