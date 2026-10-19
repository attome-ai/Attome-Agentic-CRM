import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { ConfigChange, ConfigStartRow, SecretsAdminService } from '../data/services/secrets-admin.service';

/**
 * Z1-T14 — the configuration history: each node start with its version and
 * configuration fingerprint, newest first, a page at a time. Picking two
 * starts lists the configuration keys whose values differ (secret values are
 * never stored, so a secret shows only whether it was set).
 */
@Component({
  selector: 'xrm-config-starts',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../config-admin.css'],
  template: `
    <section class="config-admin" data-config-starts>
      <h2>{{ 'configStarts.title' | translate }}</h2>
      <p class="config-intro">{{ 'configStarts.intro' | translate }}</p>
      @if (error(); as e) {
        <p class="config-error" role="alert">{{ e }}</p>
      }
      @if (loading()) {
        <p class="config-state">{{ 'configStarts.loading' | translate }}</p>
      } @else if (!starts().length) {
        <p class="config-state">{{ 'configStarts.empty' | translate }}</p>
      } @else {
        <div class="table-wrap">
          <table class="config-table">
            <thead>
              <tr>
                <th scope="col"><span class="visually-hidden">{{ 'configStarts.pick' | translate }}</span></th>
                <th scope="col">{{ 'configStarts.startedAt' | translate }}</th>
                <th scope="col">{{ 'configStarts.node' | translate }}</th>
                <th scope="col">{{ 'configStarts.version' | translate }}</th>
                <th scope="col">{{ 'configStarts.fingerprint' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (start of starts(); track start.id) {
                <tr [attr.data-start-row]="start.id">
                  <td>
                    <input type="checkbox" [attr.data-start-pick]="start.id"
                           [attr.aria-label]="'configStarts.pick' | translate"
                           [checked]="picked().includes(start.id)"
                           [disabled]="picked().length >= 2 && !picked().includes(start.id)"
                           (change)="toggle(start.id)" />
                  </td>
                  <td>{{ time(start.started_at) }}</td>
                  <td class="mono">{{ start.node_name }}</td>
                  <td class="mono">{{ start.app_version }}</td>
                  <td class="mono">{{ start.fingerprint.slice(0, 12) }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        <div class="config-actions">
          <button type="button" class="xf-btn xf-btn-secondary" data-starts-prev
                  [disabled]="page() <= 1" (click)="load(page() - 1)">{{ 'configStarts.prev' | translate }}</button>
          <span>{{ 'configStarts.page' | translate: { page: page(), pages: pages() } }}</span>
          <button type="button" class="xf-btn xf-btn-secondary" data-starts-next
                  [disabled]="page() >= pages()" (click)="load(page() + 1)">{{ 'configStarts.next' | translate }}</button>
          <button type="button" class="xf-btn xf-btn-primary" data-starts-compare
                  [disabled]="picked().length !== 2" (click)="compare()">{{ 'configStarts.compare' | translate }}</button>
        </div>
      }
      @if (changes(); as list) {
        <section class="config-diff" data-config-diff>
          <h3>{{ 'configStarts.changes' | translate }}</h3>
          @if (!list.length) {
            <p class="config-state">{{ 'configStarts.noChanges' | translate }}</p>
          } @else {
            <table class="config-table">
              <thead>
                <tr>
                  <th scope="col">{{ 'configStarts.key' | translate }}</th>
                  <th scope="col">{{ 'configStarts.before' | translate }}</th>
                  <th scope="col">{{ 'configStarts.after' | translate }}</th>
                </tr>
              </thead>
              <tbody>
                @for (change of list; track change.path) {
                  <tr [attr.data-diff-row]="change.path">
                    <th scope="row" class="mono">{{ change.path }}</th>
                    <td class="mono">{{ show(change.before) }}</td>
                    <td class="mono">{{ show(change.after) }}</td>
                  </tr>
                }
              </tbody>
            </table>
          }
        </section>
      }
    </section>
  `,
})
export class ConfigStartsComponent implements OnInit {
  private readonly svc = inject(SecretsAdminService);
  private readonly lang = inject(LangService);

  static readonly PAGE_SIZE = 25;

  readonly starts = signal<ConfigStartRow[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly pages = computed(() => Math.max(1, Math.ceil(this.total() / ConfigStartsComponent.PAGE_SIZE)));
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  /** The starts picked for a comparison, oldest first once two are picked. */
  readonly picked = signal<string[]>([]);
  /** The last comparison's changed keys; `null` before one. */
  readonly changes = signal<ConfigChange[] | null>(null);

  ngOnInit(): void {
    this.load(1);
  }

  load(page: number): void {
    this.loading.set(true);
    this.svc.starts(page, ConfigStartsComponent.PAGE_SIZE).subscribe({
      next: result => {
        this.starts.set(result.items);
        this.total.set(result.total);
        this.page.set(result.page);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  toggle(id: string): void {
    this.picked.update(ids => ids.includes(id) ? ids.filter(x => x !== id) : [...ids, id].slice(-2));
    this.changes.set(null);
  }

  /** Compares the two picked starts, the earlier one as `a`. */
  compare(): void {
    const ids = this.picked();
    if (ids.length !== 2) return;
    const at = (id: string) => this.starts().find(s => s.id === id)?.started_at ?? '';
    const [a, b] = [...ids].sort((x, y) => at(x).localeCompare(at(y)));
    this.svc.diff(a, b).subscribe({
      next: result => this.changes.set(result.items),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  show(value: unknown): string {
    if (value === null || value === undefined) return '—';
    return typeof value === 'string' ? value : JSON.stringify(value);
  }

  time(at: string): string {
    const date = new Date(at);
    return Number.isNaN(date.getTime())
      ? at
      : new Intl.DateTimeFormat(this.lang.intlLocale(), { dateStyle: 'medium', timeStyle: 'short' }).format(date);
  }
}
