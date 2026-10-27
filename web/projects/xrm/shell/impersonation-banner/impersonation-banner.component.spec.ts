import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ImpersonationService, LangService } from '@attome/base';
import type { ImpersonationSession } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ImpersonationBannerComponent } from './impersonation-banner.component';

describe('ImpersonationBannerComponent', () => {
  const session = signal<ImpersonationSession | null>(null);
  let end: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    end = vi.fn(() => {
      session.set(null);
      return of(undefined);
    });
    TestBed.configureTestingModule({
      imports: [ImpersonationBannerComponent],
      providers: [
        { provide: ImpersonationService, useValue: { session, end } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: () => 'en' } },
      ],
    });
  });

  function render(): HTMLElement {
    const fixture = TestBed.createComponent(ImpersonationBannerComponent);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('shows nothing outside a session', () => {
    session.set(null);
    expect(render().querySelector('[data-impersonation-banner]')).toBeNull();
  });

  it('shows the person, the mode and the minutes left, and ends the session', () => {
    session.set({
      id: 's1', subject_id: 'u1', mode: 'act', subject_label: 'sara@example.com',
      expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
    });
    const fixture = TestBed.createComponent(ImpersonationBannerComponent);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const banner = el.querySelector('[data-impersonation-banner]');
    expect(banner?.classList.contains('ib-act')).toBe(true);
    expect(banner?.textContent).toContain('impersonation.acting');
    expect(fixture.componentInstance.minutesLeft()).toBe(10);
    (el.querySelector('.ib-end') as HTMLButtonElement).click();
    expect(end).toHaveBeenCalled();
    fixture.detectChanges();
    expect(el.querySelector('[data-impersonation-banner]')).toBeNull();
  });

  it('says view-as when viewing', () => {
    session.set({
      id: 's2', subject_id: 'u2', mode: 'view',
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
    expect(render().querySelector('[data-impersonation-banner]')?.textContent).toContain('impersonation.viewing');
  });
});
