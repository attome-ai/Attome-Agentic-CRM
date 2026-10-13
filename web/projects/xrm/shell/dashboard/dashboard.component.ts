import { ChangeDetectionStrategy, Component, Type, computed, inject, signal } from '@angular/core';
import { NgComponentOutlet } from '@angular/common';
import { TranslatePipe } from '@attome/base';
import type { DashboardEmbedComponent } from '@attome/xrm/dashboard';
import { AppContextService } from '../services/app-context.service';

/**
 * The home page (`/xrm/dashboard`) — resolves the caller's currently
 * selected app (`AppContextService`, driven by `AppSwitcherComponent`) and
 * embeds that app's own `default_dashboard_ref` when one is set; falls back
 * to the platform-wide `general` tag when it isn't (no app selected, or the
 * selected app has no default configured) — R-10, replacing the previous
 * unconditional `tags: ['general']`.
 */
@Component({
  selector:   'attome-dashboard',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [NgComponentOutlet, TranslatePipe],
  styleUrls:  ['./dashboard.component.css'],
  templateUrl: './dashboard.component.html',
})
export class DashboardComponent {
  private readonly appContext = inject(AppContextService);

  readonly embedComponent = signal<Type<DashboardEmbedComponent> | null>(null);

  /** R-20 — set when the lazy `import('@attome/xrm/dashboard')` rejects (deploy skew, offline, a
   * failed chunk load). Without it the template's `@else` spinner never resolved. Holds an i18n
   * key, translated in the template. */
  readonly loadError = signal<string | null>(null);

  readonly embedInputs = computed(() => {
    const ref = this.appContext.selectedApp()?.default_dashboard_ref;
    return ref
      ? { dashboardId: ref, embedded: false }
      : { tags: ['general'], embedded: false };
  });

  constructor() {
    import('@attome/xrm/dashboard')
      .then(m => this.embedComponent.set(m.DashboardEmbedComponent))
      .catch(() => this.loadError.set('dashboard.shell.loadFailed'));
  }
}
