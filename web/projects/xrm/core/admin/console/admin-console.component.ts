import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import type { ApiComponents, Page } from '@attome/base';

type SettingView = ApiComponents['schemas']['SettingValueView'];
type AuditRow = ApiComponents['schemas']['AuditSearchRow'];

/** The console's areas, in navigation order (U10-T1's `setting_descriptor::area`). */
export const ADMIN_AREAS = [
  'general', 'security', 'data', 'features', 'ai', 'channels', 'sales', 'operations', 'other',
] as const;
export type AdminArea = (typeof ADMIN_AREAS)[number];

/** One admin screen, registered under an area. */
export interface AdminScreen {
  /** Catalog key of its name. */
  title: string;
  route: string;
  area: AdminArea;
}

/**
 * U10-T3 — every admin screen, by area. A new admin screen adds its row
 * here, so the console lists it and finds it by name.
 */
export const ADMIN_SCREENS: readonly AdminScreen[] = [
  { title: 'adminConsole.screen.settings', route: '/xrm/admin/settings', area: 'general' },
  { title: 'adminConsole.screen.sidebar', route: '/xrm/admin/sidebar', area: 'general' },
  { title: 'adminConsole.screen.calendars', route: '/xrm/admin/calendars', area: 'general' },
  { title: 'adminConsole.screen.secrets', route: '/xrm/admin/secrets', area: 'security' },
  { title: 'adminConsole.screen.configStarts', route: '/xrm/admin/config-starts', area: 'operations' },
  { title: 'adminConsole.screen.caches', route: '/xrm/admin/caches', area: 'operations' },
  { title: 'adminConsole.screen.dependencies', route: '/xrm/admin/dependencies', area: 'operations' },
  { title: 'adminConsole.screen.timers', route: '/xrm/admin/timers', area: 'operations' },
  { title: 'adminConsole.screen.rules', route: '/xrm/admin/rules', area: 'data' },
  { title: 'adminConsole.screen.duplicates', route: '/xrm/admin/duplicates', area: 'data' },
  { title: 'adminConsole.screen.metadataLayers', route: '/xrm/admin/metadata-layers', area: 'data' },
  { title: 'adminConsole.screen.metadataConflicts', route: '/xrm/admin/metadata-conflicts', area: 'data' },
  { title: 'adminConsole.screen.modules', route: '/xrm/admin/license/modules', area: 'features' },
];

/**
 * U10-T3 — the admin console: navigation by area, one search over every
 * setting (its key and its English and Arabic descriptions) and every admin
 * screen (its name), and the change history of a setting (who changed it and
 * when, from the audit trail).
 */
@Component({
  selector: 'xrm-admin-console',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, RouterLink],
  styleUrls: ['./admin-console.component.css'],
  template: `
    <section class="console" data-admin-console>
      <nav class="console-nav" [attr.aria-label]="'adminConsole.areas' | translate">
        <button type="button" class="console-area" [class.active]="area() === null"
                (click)="area.set(null)" data-area="all">
          {{ 'adminConsole.allAreas' | translate }}
        </button>
        @for (a of areas; track a) {
          <button type="button" class="console-area" [class.active]="area() === a"
                  (click)="area.set(a)" [attr.data-area]="a">
            {{ ('adminConsole.area.' + a) | translate }}
          </button>
        }
      </nav>

      <div class="console-main">
        <label class="console-search">
          <span class="visually-hidden">{{ 'adminConsole.search' | translate }}</span>
          <input type="search" [value]="query()" (input)="query.set($any($event.target).value)"
                 [placeholder]="'adminConsole.search' | translate" data-console-search>
        </label>

        @if (error(); as e) {
          <p class="console-error" role="alert">{{ e }}</p>
        }

        @if (screens().length) {
          <h3>{{ 'adminConsole.screens' | translate }}</h3>
          <ul class="console-list">
            @for (s of screens(); track s.route) {
              <li><a [routerLink]="s.route" [attr.data-screen]="s.route">{{ s.title | translate }}</a></li>
            }
          </ul>
        }

        <h3>{{ 'adminConsole.settings' | translate }}</h3>
        @if (loading()) {
          <p>{{ 'adminConsole.loading' | translate }}</p>
        } @else if (!settings().length) {
          <p data-console-empty>{{ 'adminConsole.noMatch' | translate }}</p>
        } @else {
          <ul class="console-list">
            @for (s of settings(); track s.key) {
              <li [attr.data-setting]="s.key">
                <button type="button" class="console-setting" (click)="open(s)">
                  <span class="mono">{{ s.key }}</span>
                  <span class="console-desc">{{ describe(s) }}</span>
                </button>
              </li>
            }
          </ul>
        }

        @if (selected(); as s) {
          <aside class="console-history" data-setting-history>
            <h3>{{ 'adminConsole.historyOf' | translate: { key: s.key } }}</h3>
            @if (historyLoading()) {
              <p>{{ 'adminConsole.loading' | translate }}</p>
            } @else if (!history().length) {
              <p data-history-empty>{{ 'adminConsole.noHistory' | translate }}</p>
            } @else {
              <ol class="console-list">
                @for (h of history(); track h.id) {
                  <li data-history-row>{{ when(h.changed_on) }} · {{ h.user_name || h.user_email }}</li>
                }
              </ol>
            }
          </aside>
        }
      </div>
    </section>
  `,
})
export class AdminConsoleComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly areas = ADMIN_AREAS;
  readonly area = signal<AdminArea | null>(null);
  readonly query = signal('');
  readonly all = signal<SettingView[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly selected = signal<SettingView | null>(null);
  readonly history = signal<AuditRow[]>([]);
  readonly historyLoading = signal(false);

  readonly settings = computed(() => {
    const area = this.area();
    const q = this.query().trim().toLowerCase();
    return this.all().filter(s =>
      (area === null || s.area === area)
      && (!q || [s.key, s.description, s.description_ar ?? ''].some(t => t.toLowerCase().includes(q))));
  });

  readonly screens = computed(() => {
    const area = this.area();
    const q = this.query().trim().toLowerCase();
    return ADMIN_SCREENS.filter(s =>
      (area === null || s.area === area)
      && (!q || this.lang.translate(s.title).toLowerCase().includes(q) || s.route.toLowerCase().includes(q)));
  });

  ngOnInit(): void {
    this.api.get<{ items: SettingView[] }>('/api/v1/admin/settings').subscribe({
      next: res => {
        this.all.set(res.items);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  describe(s: SettingView): string {
    return this.lang.current() === 'ar' && s.description_ar ? s.description_ar : s.description;
  }

  when(at: string): string {
    return new Intl.DateTimeFormat(this.lang.intlLocale(), { dateStyle: 'medium', timeStyle: 'short' })
      .format(new Date(at));
  }

  /** Shows a setting's changes: the audit trail of its row, newest first. */
  open(s: SettingView): void {
    this.selected.set(s);
    this.history.set([]);
    if (!s.id) return;
    this.historyLoading.set(true);
    this.api.get<Page<AuditRow>>('/api/v1/admin/audit/search', {
      entity_name: 'setting', record_id: s.id, page: '1', page_size: '50',
    }).subscribe({
      next: page => {
        this.history.set(page.items);
        this.historyLoading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.historyLoading.set(false);
      },
    });
  }
}
