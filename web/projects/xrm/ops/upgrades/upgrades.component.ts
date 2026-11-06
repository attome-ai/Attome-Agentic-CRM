import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, SdkService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

import { Upgrade, UpgradeDetailComponent } from './upgrade-detail.component';

interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

/** The part of `GET /api/v1/admin/license/modules` this page reads. */
interface ModuleConfiguration {
  modules: { name: string; enabled: boolean }[];
}

const PAGE_SIZE = 20;

/**
 * Upgrades (roadmap AB8-T8): the upgrade history newest first, and for the
 * chosen upgrade its check report, verification evidence, rehearsal result,
 * what changes for this deployment's switched-on modules (in the user's
 * language) and whether it can still be rolled back.
 */
@Component({
  selector: 'attome-ops-upgrades',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, LocalDatePipe, UpgradeDetailComponent],
  template: `
    <section class="up-page">
      <h2>{{ 'ops.upgrades.title' | translate }}</h2>

      @if (error(); as message) {
        <p class="up-error" role="alert">{{ message }}</p>
      }

      @if (upgrades().length > 0) {
        <div class="up-scroll">
          <table class="up-table" data-testid="up-history">
            <thead>
              <tr>
                <th scope="col">{{ 'ops.upgrades.started' | translate }}</th>
                <th scope="col">{{ 'ops.upgrades.versions' | translate }}</th>
                <th scope="col">{{ 'ops.upgrades.statusLabel' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (u of upgrades(); track u.id) {
                <tr [attr.aria-selected]="u.id === selectedId()" data-testid="up-row">
                  <td>
                    <button type="button" class="up-pick" (click)="select(u.id)">
                      {{ u.started_at ? (u.started_at | localDate) : '—' }}
                    </button>
                  </td>
                  <td dir="ltr">{{ u.from_version ?? '—' }} → {{ u.to_version ?? '—' }}</td>
                  <td [attr.data-status]="u.status">{{ 'ops.upgrades.status.' + u.status | translate }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        <div class="up-pages">
          <button type="button" [disabled]="page() <= 1" (click)="load(page() - 1)">{{ 'ops.upgrades.prev' | translate }}</button>
          <button type="button" [disabled]="page() * pageSize >= total()" (click)="load(page() + 1)">{{ 'ops.upgrades.next' | translate }}</button>
        </div>
      } @else if (loaded()) {
        <p>{{ 'ops.upgrades.none' | translate }}</p>
      }

      @if (selected(); as u) {
        <attome-ops-upgrade-detail [upgrade]="u" [enabledModules]="enabledModules()" [lang]="lang.current()" />
      }
    </section>
  `,
  styles: [`
    .up-page { padding-inline: 1rem; max-inline-size: 64rem; }
    .up-scroll { overflow-x: auto; }
    .up-table { border-collapse: collapse; inline-size: 100%; }
    .up-table th, .up-table td { padding-block: 0.375rem; padding-inline: 0.5rem; text-align: start; border-block-end: 1px solid var(--color-border); }
    .up-table tr[aria-selected='true'] { background: var(--color-surface-alt); }
    .up-pick { background: none; border: none; padding: 0; color: var(--color-primary); cursor: pointer; text-decoration: underline; }
    .up-pages { display: flex; gap: 0.5rem; margin-block: 0.5rem; }
    .up-error { color: var(--color-danger); }
    td[data-status='failed'] { color: var(--color-danger); }
  `],
})
export class UpgradesComponent implements OnInit {
  private readonly sdk = inject(SdkService);
  readonly lang = inject(LangService);

  readonly upgrades = signal<Upgrade[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly loaded = signal(false);
  readonly error = signal<string | null>(null);
  readonly selectedId = signal<string | null>(null);
  readonly enabledModules = signal<ReadonlySet<string>>(new Set());
  readonly pageSize = PAGE_SIZE;

  /** The chosen upgrade, else the newest on the page. */
  readonly selected = computed(() => {
    const list = this.upgrades();
    return list.find(u => u.id === this.selectedId()) ?? list[0] ?? null;
  });

  ngOnInit(): void {
    // Without the module list (a caller without admin rights) every impact
    // item but the platform's is left out rather than guessed.
    this.sdk.get<ModuleConfiguration>('/api/v1/admin/license/modules').subscribe({
      next: c => this.enabledModules.set(new Set((c.modules ?? []).filter(m => m.enabled).map(m => m.name))),
      error: () => this.enabledModules.set(new Set()),
    });
    this.load(1);
  }

  select(id: string): void {
    this.selectedId.set(id);
  }

  load(page: number): void {
    const query = { page: String(page), page_size: String(PAGE_SIZE) };
    this.sdk.get<Page<Upgrade>>('/api/v1/ops/upgrades', { query }).subscribe({
      next: p => {
        this.upgrades.set(p.items ?? []);
        this.total.set(p.total ?? 0);
        this.page.set(page);
        this.loaded.set(true);
      },
      error: (e: ApiError) => {
        this.loaded.set(true);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}
