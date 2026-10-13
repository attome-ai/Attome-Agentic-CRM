import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, AuthService, LangService, ThemeService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NotificationBellComponent } from './notification-bell/notification-bell.component';
import { ProfileMenuComponent } from './profile-menu/profile-menu.component';

/**
 * D-315 removed the shell's combined outside-click handler and the mutual
 * `set(false)` calls that kept the two header dropdowns from being open at
 * once. The claim was that mutual exclusion still falls out for free: clicking
 * one dropdown's trigger is a document click *outside* the other, which the
 * other's own handler already closes on.
 *
 * That is a claim about event ordering — the trigger's own (click) runs during
 * bubbling before the document-level listener — so it is asserted here rather
 * than argued. Both components are rendered together, as they are in the shell
 * header, and driven with real DOM clicks.
 */
@Component({
  standalone: true,
  imports: [NotificationBellComponent, ProfileMenuComponent],
  template: `
    <div class="header-right">
      <attome-notification-bell />
      <xrm-profile-menu />
    </div>
  `,
})
class HeaderHostComponent {}

function mount(): {
  fixture: ComponentFixture<HeaderHostComponent>;
  bell: NotificationBellComponent;
  profile: ProfileMenuComponent;
  bellBtn: HTMLElement;
  avatarBtn: HTMLElement;
} {
  TestBed.configureTestingModule({
    imports: [HeaderHostComponent],
    providers: [
      provideRouter([]),
      { provide: ApiService, useValue: {
        post: () => of({ notifications: [], unread_count: 0 }),
        // D-404 / M83 Phase 1: ProfileMenuComponent's timezone-preference fetch
        // (EntityService.get -> ApiService.get) needs this mocked too.
        get: () => of({ data: {} }),
      } },
      { provide: AuthService, useValue: { userId: signal('user-id'), logout: () => of(undefined) } },
      {
        provide: ThemeService,
        useValue: { mode: signal('light'), setMode: vi.fn() },
      },
      { provide: LangService, useValue: { current: signal('en'), set: vi.fn(), translate: (key: string) => key } },
    ],
  });
  const fixture = TestBed.createComponent(HeaderHostComponent);
  fixture.detectChanges();
  const el: HTMLElement = fixture.nativeElement;
  return {
    fixture,
    bell:      fixture.debugElement.children[0].children[0].componentInstance,
    profile:   fixture.debugElement.children[0].children[1].componentInstance,
    bellBtn:   el.querySelector('.icon-btn')!,
    avatarBtn: el.querySelector('.avatar-btn')!,
  };
}

// The components listen on `document`, so events must reach it — a bare
// dispatchEvent on a detached fixture root would not bubble that far.
function clickInDocument(target: HTMLElement, fixture: ComponentFixture<unknown>): void {
  document.body.appendChild(fixture.nativeElement);
  target.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  fixture.detectChanges();
}

describe('header dropdowns are mutually exclusive without a coordinator', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('opening the profile menu closes an open notification panel', () => {
    const { fixture, bell, profile, bellBtn, avatarBtn } = mount();

    clickInDocument(bellBtn, fixture);
    expect(bell.isOpen()).toBe(true);
    expect(profile.isOpen()).toBe(false);

    clickInDocument(avatarBtn, fixture);
    expect(profile.isOpen()).toBe(true);
    expect(bell.isOpen()).toBe(false);
  });

  it('opening the notification panel closes an open profile menu', () => {
    const { fixture, bell, profile, bellBtn, avatarBtn } = mount();

    clickInDocument(avatarBtn, fixture);
    expect(profile.isOpen()).toBe(true);

    clickInDocument(bellBtn, fixture);
    expect(bell.isOpen()).toBe(true);
    expect(profile.isOpen()).toBe(false);
  });

  it('a click elsewhere in the document closes both', () => {
    const { fixture, bell, profile, bellBtn } = mount();
    clickInDocument(bellBtn, fixture);
    expect(bell.isOpen()).toBe(true);

    const outside = document.createElement('div');
    document.body.appendChild(outside);
    clickInDocument(outside, fixture);

    expect(bell.isOpen()).toBe(false);
    expect(profile.isOpen()).toBe(false);
  });

  it('clicking inside an open panel does not close it', () => {
    const { fixture, bell, bellBtn } = mount();
    clickInDocument(bellBtn, fixture);
    expect(bell.isOpen()).toBe(true);

    const panel: HTMLElement = fixture.nativeElement.querySelector('.notif-panel');
    clickInDocument(panel, fixture);

    expect(bell.isOpen()).toBe(true);
  });
});

// U15 — the approver's inbox is reached from the profile menu.
describe('profile menu', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('links to My approvals and closes when the link is followed', () => {
    const { fixture, profile, avatarBtn } = mount();
    clickInDocument(avatarBtn, fixture);
    const link: HTMLAnchorElement = fixture.nativeElement.querySelector('[data-testid="profile-my-approvals"]');
    expect(link.getAttribute('href')).toBe('/xrm/my-work/approvals');
    expect(link.textContent).toContain('shell.myApprovals');
    // Ctrl-click: RouterLink leaves a modified click to the browser, so the
    // test route table (empty) is never asked to match; the menu's own
    // (click) handler still runs.
    link.addEventListener('click', e => e.preventDefault());
    link.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, ctrlKey: true }));
    fixture.detectChanges();
    expect(profile.isOpen()).toBe(false);
  });
});
