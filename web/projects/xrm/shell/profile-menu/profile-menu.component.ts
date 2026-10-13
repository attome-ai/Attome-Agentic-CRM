import {
  ChangeDetectionStrategy, Component, effect, ElementRef, inject, signal, viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import {
  AuthService, Lang, LangService, ThemeMode, ThemeService, TranslatePipe, UserPreferencesService,
} from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { EntityService } from '@attome/xrm/core/entity';

/**
 * The header's avatar button and its profile dropdown — theme, language and
 * sign-out (D-315).
 *
 * Extracted whole from `ShellComponent`. The panel is `position: fixed` and
 * measured against its anchor, which is why `positionProfilePanel()` and the
 * resize handler come with it; the anchor is now this component's host element
 * rather than the `.hdr-wrap` div it replaces. Those are the same rectangle —
 * the panel is out of flow, so it never contributed to the wrapper's box.
 *
 * D-404 / M83 Phase 1: also the one place that resolves the signed-in user's
 * own `user_account.timezone` into `UserPreferencesService` — this
 * component is mounted for every authenticated page, so it is a natural,
 * already-live hook rather than a new app-wide bootstrap mechanism. `@attome
 * /base`'s `LocalDatePipe` reads that signal; nothing here renders a date
 * itself.
 */
@Component({
  selector:   'xrm-profile-menu',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, RouterLink],
  host: {
    '(document:click)': 'onDocumentClick($event)',
    '(window:resize)':  'onWindowResize()',
  },
  styleUrls: ['../header-dropdown.css', './profile-menu.component.css'],
  templateUrl: './profile-menu.component.html',
})
export class ProfileMenuComponent {
  private readonly auth          = inject(AuthService);
  private readonly themeService  = inject(ThemeService);
  private readonly langService   = inject(LangService);
  private readonly host          = inject(ElementRef<HTMLElement>);
  private readonly entityService = inject(EntityService);
  private readonly userPrefs     = inject(UserPreferencesService);
  private readonly dialog        = inject(DialogService);

  readonly isOpen = signal(false);
  readonly profilePanelRef = viewChild<ElementRef<HTMLElement>>('profilePanel');

  // NGB-4.1: the service exposes the signal directly, so the template reads the
  // same value without an observable bridge.
  readonly themeMode   = this.themeService.mode;
  readonly currentLang = this.langService.current;

  private lastTimezoneFetchFor: string | null = null;

  constructor() {
    // Fetches the current user's own record once per login (`auth.userId()`
    // changing is exactly "a new session started" — `restoreSession`/
    // `bootstrapSession`/`logout` are the only writers). A failed fetch
    // (network, not-yet-authorized) just leaves the preference unset —
    // `LocalDatePipe` already falls back to the browser timezone.
    effect(() => {
      const userId = this.auth.userId();
      if (!userId || userId === this.lastTimezoneFetchFor) {
        if (!userId) this.userPrefs.setTimezone(null);
        return;
      }
      this.lastTimezoneFetchFor = userId;
      this.entityService.get('user_account', userId).subscribe({
        next: record => this.userPrefs.setTimezone(record.data['timezone'] as string | undefined),
        error: () => this.userPrefs.setTimezone(null),
      });
    });
  }

  initial(): string { return (this.auth.userId() ?? 'U').slice(0, 1).toUpperCase(); }
  shortId(): string { return (this.auth.userId() ?? '').slice(0, 14); }
  /**
   * NGB-1.1: a failed sign-out is never silent — on a shared machine the user
   * would walk away from a live session. Say so, and offer a retry.
   */
  logout(): void {
    this.auth.logout().subscribe({
      error: async () => {
        const retry = await this.dialog.confirm({
          title:       this.langService.translate('shell.signOutFailedTitle'),
          message:     this.langService.translate('shell.signOutFailed'),
          confirmText: this.langService.translate('shell.signOutRetry'),
          variant:     'danger',
        });
        if (retry) this.logout();
      },
    });
  }

  toggle(): void {
    const opening = !this.isOpen();
    this.isOpen.set(opening);
    if (opening) requestAnimationFrame(() => this.positionPanel());
  }

  onDocumentClick(e: MouseEvent): void {
    if (this.isOpen() && !this.host.nativeElement.contains(e.target)) {
      this.isOpen.set(false);
    }
  }

  onWindowResize(): void {
    if (this.isOpen()) this.positionPanel();
  }

  setThemeMode(mode: ThemeMode): void { this.themeService.setMode(mode); }

  setLang(lang: Lang): void {
    this.langService.set(lang);
    requestAnimationFrame(() => this.positionPanel());
  }

  private positionPanel(): void {
    const anchor = this.host.nativeElement as HTMLElement | undefined;
    const panel = this.profilePanelRef()?.nativeElement;
    if (!anchor || !panel) return;

    const margin = 12;
    const anchorRect = anchor.getBoundingClientRect();
    const panelWidth = Math.min(260, window.innerWidth - margin * 2);
    const left = Math.min(
      Math.max(anchorRect.right - panelWidth, margin),
      window.innerWidth - panelWidth - margin,
    );
    const top = Math.min(anchorRect.bottom + 10, window.innerHeight - margin);

    panel.style.width = `${panelWidth}px`;
    panel.style.left = `${left}px`;
    panel.style.right = 'auto';
    panel.style.top = `${top}px`;
    panel.style.maxHeight = `${Math.max(0, window.innerHeight - top - margin)}px`;
    panel.style.overflowY = 'auto';
  }
}
