import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import type { ApiError } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NotificationPreferences, NotificationPreferencesService } from './notification-preferences.service';
import { NotificationPreferencesPageComponent, quietHoursValue } from './notification-preferences-page.component';

function doc(items: NotificationPreferences['items'] = []): NotificationPreferences {
  return { categories: ['sla_warning', 'reminder'], channels: ['in_app', 'email', 'sms', 'push', 'chat'], items };
}

describe('NotificationPreferencesPageComponent', () => {
  let svc: { load: ReturnType<typeof vi.fn>; save: ReturnType<typeof vi.fn> };
  let api: { get: ReturnType<typeof vi.fn>; put: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    svc = { load: vi.fn(), save: vi.fn() };
    api = {
      get: vi.fn(() => of({ items: [
        { key: 'notification.digest', value: 'daily' },
        { key: 'notification.quiet_hours', value: { start: '22:00', end: '07:00' } },
      ] })),
      put: vi.fn(() => of({})),
    };
    TestBed.configureTestingModule({
      imports: [NotificationPreferencesPageComponent],
      providers: [
        { provide: NotificationPreferencesService, useValue: svc },
        { provide: ApiService, useValue: api },
        {
          provide: LangService,
          useValue: {
            intlLocale: () => 'en-US',
            translate: (key: string, params?: Record<string, unknown>) =>
              params ? `${key} ${JSON.stringify(params)}` : key,
          },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(NotificationPreferencesPageComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const q = <T extends HTMLElement = HTMLElement>(testId: string) =>
      el.querySelector<T>(`[data-testid="${testId}"]`);
    const qa = (testId: string) => Array.from(el.querySelectorAll<HTMLElement>(`[data-testid="${testId}"]`));
    return { fixture, el, q, qa };
  }

  it('lists one row per category, with every channel on when nothing is stored', () => {
    svc.load.mockReturnValue(of(doc()));
    const { q, qa } = render();
    expect(qa('notification-prefs-row').length).toBe(2);
    expect(q<HTMLInputElement>('notification-prefs-toggle-reminder-email')?.checked).toBe(true);
    expect(q<HTMLInputElement>('notification-prefs-toggle-sla_warning-in_app')?.checked).toBe(true);
    // The platform event gets its translated label; a template key shows as is.
    expect(qa('notification-prefs-row')[1].textContent).toContain('notificationPrefs.category.reminder');
    expect(qa('notification-prefs-row')[0].textContent).toContain('sla_warning');
  });

  it('shows a stored mute as unchecked', () => {
    svc.load.mockReturnValue(of(doc([{ category: 'reminder', channel: 'email', enabled: false, row_version: 3 }])));
    const { q } = render();
    expect(q<HTMLInputElement>('notification-prefs-toggle-reminder-email')?.checked).toBe(false);
    expect(q<HTMLInputElement>('notification-prefs-toggle-reminder-in_app')?.checked).toBe(true);
  });

  it('mutes a channel with no stored row, sending no row_version', () => {
    svc.load.mockReturnValue(of(doc()));
    svc.save.mockReturnValue(of(doc([{ category: 'reminder', channel: 'email', enabled: false, row_version: 0 }])));
    const { fixture, q } = render();
    q<HTMLInputElement>('notification-prefs-toggle-reminder-email')!.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(svc.save).toHaveBeenCalledWith([{ category: 'reminder', channel: 'email', enabled: false, row_version: null }]);
    expect(q<HTMLInputElement>('notification-prefs-toggle-reminder-email')?.checked).toBe(false);
    expect(q('notification-prefs-notice')?.textContent).toContain('notificationPrefs.turnedOff');
  });

  it('unmutes a stored row with its row_version', () => {
    svc.load.mockReturnValue(of(doc([{ category: 'reminder', channel: 'email', enabled: false, row_version: 4 }])));
    svc.save.mockReturnValue(of(doc([{ category: 'reminder', channel: 'email', enabled: true, row_version: 5 }])));
    const { fixture, q } = render();
    q<HTMLInputElement>('notification-prefs-toggle-reminder-email')!.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(svc.save).toHaveBeenCalledWith([{ category: 'reminder', channel: 'email', enabled: true, row_version: 4 }]);
  });

  it('explains a conflict and reloads the table', () => {
    svc.load.mockReturnValue(of(doc()));
    const err: ApiError = { kind: 'version_conflict', status: 409, message: 'stale' };
    svc.save.mockReturnValue(throwError(() => err));
    const { fixture, q } = render();
    q<HTMLInputElement>('notification-prefs-toggle-reminder-in_app')!.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(svc.load).toHaveBeenCalledTimes(2);
    expect(q('notification-prefs-error')?.getAttribute('role')).toBe('alert');
  });

  it('surfaces a load failure as an alert', () => {
    const err: ApiError = { kind: 'internal', status: 500, message: 'Internal server error' };
    svc.load.mockReturnValue(throwError(() => err));
    const { q } = render();
    expect(q('notification-prefs-error')?.textContent).toContain('Internal server error');
  });

  it('M15-T3: shows and saves the digest and quiet hours', () => {
    svc.load.mockReturnValue(of(doc()));
    const { fixture } = render();
    const component = fixture.componentInstance;
    expect(component.digest).toBe('daily');
    expect(component.quietStart).toBe('22:00');
    component.digest = 'hourly';
    component.quietEnd = '06:30';
    component.saveDelivery();
    expect(api.put).toHaveBeenCalledWith('/api/v1/settings/me/notification.digest', { value: 'hourly' });
    expect(api.put).toHaveBeenCalledWith('/api/v1/settings/me/notification.quiet_hours', {
      value: { start: '22:00', end: '06:30' },
    });
  });

  it('M15-T3: clears quiet hours unless both times are set', () => {
    expect(quietHoursValue('22:00', '')).toEqual({});
    expect(quietHoursValue('22:00', '22:00')).toEqual({});
    expect(quietHoursValue('25:00', '07:00')).toEqual({});
    expect(quietHoursValue('22:00', '07:00')).toEqual({ start: '22:00', end: '07:00' });
  });
});
