import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG } from './config';
import { LangService } from './lang.service';
import { IdleSessionService } from './idle-session.service';
import { IdleWarningComponent } from './idle-warning.component';

describe('IdleWarningComponent', () => {
  const API = 'http://localhost:7865';
  let http: HttpTestingController;

  beforeEach(() => {
    vi.useFakeTimers();
    TestBed.configureTestingModule({
      imports: [IdleWarningComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    });
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    TestBed.inject(IdleSessionService).stop();
    vi.useRealTimers();
  });

  it('warning appears 60 s before expiry', () => {
    const idle = TestBed.inject(IdleSessionService);
    const expired = vi.fn();
    idle.start(180, expired);
    const fixture = TestBed.createComponent(IdleWarningComponent);
    fixture.detectChanges();
    const text = () => (fixture.nativeElement as HTMLElement).textContent ?? '';

    vi.advanceTimersByTime(119_000);
    fixture.detectChanges();
    expect(text()).not.toContain('idleWarning.stay');

    vi.advanceTimersByTime(2_000);
    fixture.detectChanges();
    expect(idle.warning()).toBe(true);
    expect(text()).toContain('idleWarning.stay');
    expect(expired).not.toHaveBeenCalled();
  });

  it('staying signed in hides the warning and tells the server', () => {
    const idle = TestBed.inject(IdleSessionService);
    idle.start(90, vi.fn());
    const fixture = TestBed.createComponent(IdleWarningComponent);
    vi.advanceTimersByTime(40_000);
    fixture.detectChanges();
    expect(idle.warning()).toBe(true);

    ((fixture.nativeElement as HTMLElement).querySelector('[data-testid="idle-stay"]') as HTMLButtonElement).click();
    http.expectOne(`${API}/api/v1/auth/session`).flush({ user_id: 'u', email: 'e' });
    fixture.detectChanges();
    expect(idle.warning()).toBe(false);
  });

  it('signs out at the limit after asking open forms to keep a draft', () => {
    const idle = TestBed.inject(IdleSessionService);
    const order: string[] = [];
    idle.beforeIdleSignOut.subscribe(() => order.push('draft'));
    idle.start(70, () => order.push('signed out'));
    vi.advanceTimersByTime(71_000);
    expect(order).toEqual(['draft', 'signed out']);
  });
});
