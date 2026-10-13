import {
  ChangeDetectionStrategy, Component, ElementRef, OnInit, computed, inject, output, signal,
} from '@angular/core';
import { ApiService, TranslatePipe } from '@attome/base';
import { AppContextService, AvailableApp } from '../services/app-context.service';

export type { AvailableApp };

/**
 * M65 Phase 1 (D-467) — the header's app switcher. Lists every app the
 * caller may see (`roles[]` visibility only, already filtered server-side by
 * `list_available_apps`) and, on selection, emits the chosen app's
 * `entities[]` so `ShellComponent` can narrow the sidebar tree to that
 * subtree.
 *
 * **"Apps only filter, never authorize" (D-467).** This component and the
 * filter it drives are a pure navigation convenience: nothing here is
 * consulted by any privilege check. Clearing the selection (or a deployment
 * with no apps configured at all — the common case until an admin sets one
 * up) shows the caller's full, normal sidebar, identical to before this
 * feature existed.
 *
 * Same "simple CSS-positioned dropdown, no viewport-clamping math" posture
 * `notification-bell.component.ts` already uses — `header-dropdown.css`'s
 * `.hdr-panel` handles positioning entirely in CSS.
 */
@Component({
  selector: 'xrm-app-switcher',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  host: {
    '(document:click)': 'onDocumentClick($event)',
  },
  styleUrls: ['../header-dropdown.css', './app-switcher.component.css'],
  templateUrl: './app-switcher.component.html',
})
export class AppSwitcherComponent implements OnInit {
  private readonly api  = inject(ApiService);
  private readonly host = inject(ElementRef<HTMLElement>);
  private readonly appContext = inject(AppContextService);

  /** Emits the selected app's `entities[]`, or `null` when the caller clears
   * the selection back to "All apps" — `ShellComponent` treats `null` as
   * "show the full, unfiltered sidebar". */
  readonly appChanged = output<string[] | null>();

  readonly apps   = signal<AvailableApp[]>([]);
  readonly isOpen = signal(false);

  // Sourced from `AppContextService`, not a local signal — that service owns
  // both the persisted selection (`localStorage`) and the resolved
  // `apps().find(...)` lookup, so a stale/removed stored app id degrades to
  // "no selection" the same way it always did, with no duplicate storage
  // read here (R-10).
  readonly selectedApp = computed(() => this.appContext.selectedApp());

  ngOnInit(): void {
    this.api.get<AvailableApp[]>('/api/v1/apps').subscribe({
      next: apps => {
        this.apps.set(apps);
        this.appContext.setApps(apps);
        const selected = this.appContext.selectedApp();
        if (selected) this.appChanged.emit(selected.entities);
      },
      // A failed fetch just leaves the switcher empty (hidden — see the
      // template's `@if (apps().length > 0)`) rather than blocking the shell;
      // this is a navigation convenience, not something the rest of the page
      // depends on.
      error: () => { this.apps.set([]); this.appContext.setApps([]); },
    });
  }

  toggle(): void {
    this.isOpen.update(open => !open);
  }

  onDocumentClick(e: MouseEvent): void {
    if (this.isOpen() && !this.host.nativeElement.contains(e.target)) {
      this.isOpen.set(false);
    }
  }

  select(app: AvailableApp): void {
    this.appContext.select(app.id);
    this.isOpen.set(false);
    this.appChanged.emit(app.entities);
  }

  clear(): void {
    this.appContext.select(null);
    this.isOpen.set(false);
    this.appChanged.emit(null);
  }
}
