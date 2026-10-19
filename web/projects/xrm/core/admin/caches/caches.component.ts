import { ChangeDetectionStrategy, Component, inject, OnInit, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { CacheAdminService, CacheStatsRow } from '../data/services/cache-admin.service';

/**
 * Z3-T10 — the admin caches screen: every declared cache built on the node
 * that answered, with its entries, hit rate, and evictions, and a purge of
 * one key or the whole cache. The purge is audited and reaches every node
 * (Z3-T9). No cached value is shown, and the server sends none.
 */
@Component({
  selector: 'xrm-caches',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../config-admin.css'],
  template: `
    <section class="config-admin" data-caches>
      <h2>{{ 'cachesAdmin.title' | translate }}</h2>
      <p class="config-intro">
        {{ 'cachesAdmin.intro' | translate }}
        @if (node(); as n) {
          {{ 'cachesAdmin.node' | translate: { node: n } }}
        }
      </p>
      @if (notice(); as n) {
        <p class="config-state" role="status" data-caches-notice>{{ n }}</p>
      }
      @if (error(); as e) {
        <p class="config-error" role="alert">{{ e }}</p>
      } @else if (loading()) {
        <p class="config-state">{{ 'cachesAdmin.loading' | translate }}</p>
      } @else if (!rows().length) {
        <p class="config-state">{{ 'cachesAdmin.empty' | translate }}</p>
      } @else {
        <div class="table-wrap">
          <table class="config-table">
            <thead>
              <tr>
                <th scope="col">{{ 'cachesAdmin.name' | translate }}</th>
                <th scope="col">{{ 'cachesAdmin.entries' | translate }}</th>
                <th scope="col">{{ 'cachesAdmin.hitRate' | translate }}</th>
                <th scope="col">{{ 'cachesAdmin.evictions' | translate }}</th>
                <th scope="col"><span class="visually-hidden">{{ 'cachesAdmin.actions' | translate }}</span></th>
              </tr>
            </thead>
            <tbody>
              @for (row of rows(); track row.name) {
                <tr [attr.data-cache-row]="row.name">
                  <th scope="row" class="mono">{{ row.name }}</th>
                  <td>{{ count(row.entries) }}</td>
                  <td data-hit-rate>{{ hitRate(row) }}</td>
                  <td>{{ count(row.evictions) }}</td>
                  <td>
                    <button type="button" class="config-action" (click)="ask(row.name)"
                            [disabled]="purging()" [attr.data-purge]="row.name">
                      {{ 'cachesAdmin.purge' | translate }}
                    </button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
      @if (confirming(); as name) {
        <div class="config-confirm" role="dialog" aria-labelledby="caches-confirm-title" data-purge-confirm>
          <h3 id="caches-confirm-title">{{ 'cachesAdmin.confirmTitle' | translate: { name } }}</h3>
          <p class="config-intro">{{ 'cachesAdmin.confirmBody' | translate }}</p>
          <label class="config-field">
            <span>{{ 'cachesAdmin.key' | translate }}</span>
            <input type="text" class="mono" maxlength="512" [value]="key()"
                   (input)="key.set($any($event.target).value)" data-purge-key>
          </label>
          <div class="config-actions">
            <button type="button" class="config-action config-action-danger" (click)="purge()"
                    [disabled]="purging()" data-purge-go>
              {{ (key().trim() ? 'cachesAdmin.purgeKey' : 'cachesAdmin.purgeAll') | translate }}
            </button>
            <button type="button" class="config-action" (click)="cancel()" [disabled]="purging()">
              {{ 'cachesAdmin.cancel' | translate }}
            </button>
          </div>
        </div>
      }
    </section>
  `,
})
export class CachesComponent implements OnInit {
  private readonly svc = inject(CacheAdminService);
  private readonly lang = inject(LangService);

  readonly rows = signal<CacheStatsRow[]>([]);
  readonly node = signal<string | null>(null);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  /** The cache whose purge is being confirmed. */
  readonly confirming = signal<string | null>(null);
  readonly key = signal('');
  readonly purging = signal(false);

  ngOnInit(): void {
    this.load();
  }

  /** hits / (hits + misses) as a percentage, or a dash before the first read. */
  hitRate(row: CacheStatsRow): string {
    const reads = row.hits + row.misses;
    if (reads === 0) return '—';
    return new Intl.NumberFormat(this.lang.intlLocale(), { style: 'percent', maximumFractionDigits: 1 })
      .format(row.hits / reads);
  }

  count(n: number): string {
    return new Intl.NumberFormat(this.lang.intlLocale()).format(n);
  }

  ask(name: string): void {
    this.notice.set(null);
    this.key.set('');
    this.confirming.set(name);
  }

  cancel(): void {
    this.confirming.set(null);
  }

  purge(): void {
    const name = this.confirming();
    if (!name) return;
    const key = this.key().trim() || null;
    this.purging.set(true);
    this.svc.purge(name, key).subscribe({
      next: () => {
        this.purging.set(false);
        this.confirming.set(null);
        this.notice.set(this.lang.translate(key ? 'cachesAdmin.purgedKey' : 'cachesAdmin.purgedAll', { name }));
        this.load();
      },
      error: (e: ApiError) => {
        this.purging.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  private load(): void {
    this.svc.list().subscribe({
      next: page => {
        this.rows.set(page.items);
        this.node.set(page.items[0]?.node ?? null);
        this.error.set(null);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }
}
