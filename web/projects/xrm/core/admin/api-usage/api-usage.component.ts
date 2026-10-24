import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  ApiUsageService, MAX_KEY_QUOTA, USAGE_WINDOWS,
  type ApiKeyUsageRow, type ApiUsageSummaryRow,
} from '@attome/xrm/core/admin/data';

/** What a quota field holds: a whole number in range, an empty field
 * (no quota), or neither. Pure. */
export function parseQuota(text: string): { ok: true; value: number | null } | { ok: false } {
  const t = text.trim();
  if (t === '') return { ok: true, value: null };
  if (!/^\d+$/.test(t)) return { ok: false };
  const n = Number(t);
  return n >= 1 && n <= MAX_KEY_QUOTA ? { ok: true, value: n } : { ok: false };
}

/**
 * S10-T1 — `/xrm/admin/api-usage`: every API key with its owner, its
 * requests over the window and its own per-minute quota (set or cleared in
 * place; the rate limiter enforces it across every route the key calls),
 * and the most requested routes. Counts come from the nightly rollup, so
 * today's requests show tomorrow. `system.admin` only, like the API.
 */
@Component({
  selector: 'xrm-api-usage',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, LocalNumberPipe, TranslatePipe],
  styleUrls: ['../../../styles/admin-page.css', './api-usage.component.css'],
  template: `
    <div class="page-header">
      <div>
        <h2>{{ 'apiUsage.title' | translate }}</h2>
        <p class="subtitle">{{ 'apiUsage.subtitle' | translate }}</p>
      </div>
      <label class="au-window">{{ 'apiUsage.window' | translate }}
        <select data-usage-window [ngModel]="days()" (ngModelChange)="setDays($event)">
          @for (d of windows; track d) {
            <option [ngValue]="d">{{ 'apiUsage.days' | translate: { count: d } }}</option>
          }
        </select>
      </label>
    </div>

    @if (notice(); as n) { <p class="au-notice" role="status" aria-live="polite">{{ n | translate }}</p> }

    <section class="card" aria-labelledby="au-keys-title">
      <h3 id="au-keys-title">{{ 'apiUsage.keys' | translate }} <span class="count">{{ keysTotal() | localNumber }}</span></h3>
      @if (keysLoading()) {
        <p class="state-msg">{{ 'apiUsage.loading' | translate }}</p>
      } @else if (keysError(); as e) {
        <p class="error-msg" role="alert">{{ e }}</p>
      } @else if (keys().length === 0) {
        <p class="state-msg">{{ 'apiUsage.noKeys' | translate }}</p>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{{ 'apiUsage.key' | translate }}</th>
                <th scope="col">{{ 'apiUsage.owner' | translate }}</th>
                <th scope="col">{{ 'apiUsage.requests' | translate }}</th>
                <th scope="col">{{ 'apiUsage.lastUsed' | translate }}</th>
                <th scope="col">{{ 'apiUsage.quota' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (k of keys(); track k.id) {
                <tr data-usage-key [attr.data-id]="k.id" [class.au-inactive]="!k.is_active">
                  <td>
                    <span>{{ k.name }}</span>
                    <span class="hint cell-mono" dir="ltr">{{ k.public_key }}</span>
                    @if (!k.is_active) { <span class="badge">{{ 'apiUsage.revoked' | translate }}</span> }
                  </td>
                  <td>{{ k.owner_name || k.owner_id }}</td>
                  <td>{{ k.total_requests | localNumber }}</td>
                  <td class="cell-muted">
                    @if (k.last_used_at) { {{ k.last_used_at | localDate: { dateStyle: 'medium', timeStyle: 'short' } }} }
                    @else { {{ 'apiUsage.never' | translate }} }
                  </td>
                  <td>
                    <form class="au-quota" (ngSubmit)="saveQuota(k)">
                      <input class="mono-input" inputmode="numeric" data-quota-input
                             [attr.aria-label]="'apiUsage.quotaFor' | translate: { name: k.name }"
                             [name]="'q-' + k.id" [placeholder]="'apiUsage.noQuota' | translate"
                             [ngModel]="draft(k)" (ngModelChange)="setDraft(k.id, $event)" />
                      <span class="hint">{{ 'apiUsage.perMinute' | translate }}</span>
                      <button type="submit" class="btn-sm" data-quota-save [disabled]="savingId() === k.id || !changed(k)">
                        {{ 'apiUsage.save' | translate }}
                      </button>
                    </form>
                    @if (invalidId() === k.id) {
                      <p class="error-msg" role="alert">{{ 'apiUsage.invalidQuota' | translate: { max: maxQuota } }}</p>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        @if (keyPages() > 1) {
          <nav class="au-pager" [attr.aria-label]="'apiUsage.pagination' | translate">
            <button type="button" class="btn-ghost" (click)="keyPage(-1)" [disabled]="keysPage() <= 1">{{ 'apiUsage.previous' | translate }}</button>
            <span>{{ 'apiUsage.pageOf' | translate: { page: keysPage(), pages: keyPages() } }}</span>
            <button type="button" class="btn-ghost" (click)="keyPage(1)" [disabled]="keysPage() >= keyPages()">{{ 'apiUsage.next' | translate }}</button>
          </nav>
        }
      }
    </section>

    <section class="card" aria-labelledby="au-routes-title">
      <h3 id="au-routes-title">{{ 'apiUsage.routes' | translate }}</h3>
      @if (routesError(); as e) {
        <p class="error-msg" role="alert">{{ e }}</p>
      } @else if (routes().length === 0) {
        <p class="state-msg">{{ 'apiUsage.noRoutes' | translate }}</p>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{{ 'apiUsage.route' | translate }}</th>
                <th scope="col">{{ 'apiUsage.caller' | translate }}</th>
                <th scope="col">{{ 'apiUsage.requests' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (r of routes(); track r.method + r.route_template + r.identity_kind + r.identity_label) {
                <tr data-usage-route>
                  <td class="cell-mono" dir="ltr">{{ r.method }} {{ r.route_template }}</td>
                  <td>
                    <span class="badge">{{ 'apiUsage.kinds.' + r.identity_kind | translate }}</span>
                    <span class="hint cell-mono" dir="ltr">{{ keyName(r) }}</span>
                  </td>
                  <td>{{ r.total_requests | localNumber }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </section>
  `,
})
export class ApiUsageComponent implements OnInit {
  private readonly svc = inject(ApiUsageService);
  private readonly destroyRef = inject(DestroyRef);

  readonly windows = USAGE_WINDOWS;
  readonly maxQuota = MAX_KEY_QUOTA;
  readonly pageSize = 50;

  readonly days = signal<number>(7);
  readonly keys = signal<ApiKeyUsageRow[]>([]);
  readonly keysTotal = signal(0);
  readonly keysPage = signal(1);
  readonly keysLoading = signal(true);
  readonly keysError = signal<string | null>(null);
  readonly routes = signal<ApiUsageSummaryRow[]>([]);
  readonly routesError = signal<string | null>(null);

  /** Quota fields being edited, by key id. */
  private readonly drafts = signal<Record<string, string>>({});
  readonly savingId = signal<string | null>(null);
  readonly invalidId = signal<string | null>(null);
  readonly notice = signal<string | null>(null);

  readonly keyPages = computed(() => Math.max(1, Math.ceil(this.keysTotal() / this.pageSize)));
  private readonly names = computed(() => new Map(this.keys().map(k => [k.id, k.name])));

  ngOnInit(): void {
    this.load();
  }

  setDays(days: number): void {
    this.days.set(Number(days));
    this.keysPage.set(1);
    this.load();
  }

  keyPage(step: number): void {
    const next = this.keysPage() + step;
    if (next < 1 || next > this.keyPages()) return;
    this.keysPage.set(next);
    this.loadKeys();
  }

  /** The quota field's text: the draft, else the key's quota. */
  draft(key: ApiKeyUsageRow): string {
    return this.drafts()[key.id] ?? (key.requests_per_minute ? String(key.requests_per_minute) : '');
  }

  setDraft(id: string, text: string): void {
    this.drafts.update(d => ({ ...d, [id]: text }));
    if (this.invalidId() === id) this.invalidId.set(null);
  }

  changed(key: ApiKeyUsageRow): boolean {
    const parsed = parseQuota(this.draft(key));
    return !parsed.ok || parsed.value !== (key.requests_per_minute ?? null);
  }

  /** A usage row's key name, when the caller is a key on this page. */
  keyName(row: ApiUsageSummaryRow): string {
    return (row.identity_kind === 'api_key' && this.names().get(row.identity_label)) || row.identity_label;
  }

  saveQuota(key: ApiKeyUsageRow): void {
    const parsed = parseQuota(this.draft(key));
    if (!parsed.ok) {
      this.invalidId.set(key.id);
      return;
    }
    this.savingId.set(key.id);
    this.notice.set(null);
    this.svc.setQuota(key.id, parsed.value).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: set => {
        this.savingId.set(null);
        this.keys.update(list => list.map(k => (k.id === key.id ? { ...k, requests_per_minute: set.requests_per_minute ?? null } : k)));
        this.drafts.update(d => {
          const rest = { ...d };
          delete rest[key.id];
          return rest;
        });
        this.notice.set(set.requests_per_minute ? 'apiUsage.quotaSaved' : 'apiUsage.quotaCleared');
      },
      error: (e: ApiError) => {
        this.savingId.set(null);
        this.keysError.set(e.message);
      },
    });
  }

  private load(): void {
    this.loadKeys();
    this.svc.summary(this.days()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: page => { this.routes.set(page.items); this.routesError.set(null); },
      error: (e: ApiError) => this.routesError.set(e.message),
    });
  }

  private loadKeys(): void {
    this.keysLoading.set(true);
    this.keysError.set(null);
    this.svc.keys(this.days(), this.keysPage(), this.pageSize).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: page => {
        this.keys.set(page.items);
        this.keysTotal.set(page.total);
        this.keysLoading.set(false);
      },
      error: (e: ApiError) => { this.keysError.set(e.message); this.keysLoading.set(false); },
    });
  }
}
