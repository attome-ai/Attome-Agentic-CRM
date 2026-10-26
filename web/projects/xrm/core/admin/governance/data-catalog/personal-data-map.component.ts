import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LangService, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { DataCatalogService, type PersonalDataItem } from '@attome/xrm/core/admin/data';

/**
 * L4-T6: where every personal, financial and health attribute lives and
 * what reads it (stored queries and reports, flows, dashboards, rules), from
 * `GET /api/v1/catalog/personal-data-map`. Only attributes the person may see.
 */
@Component({
  selector: 'xrm-catalog-personal-data-map',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalNumberPipe, TranslatePipe],
  styleUrls: ['./catalog-assets.css'],
  template: `
    <section class="card" aria-labelledby="pdm-title" data-testid="personal-data-map">
      <h3 id="pdm-title">
        {{ 'governance.catalog.assets.personalMap' | translate }}
        <span class="count">{{ total() | localNumber }}</span>
      </h3>
      <p class="gov-muted">{{ 'governance.catalog.assets.personalMapHint' | translate }}</p>
      @if (loading()) {
        <p class="state-msg">{{ 'governance.common.loading' | translate }}</p>
      } @else if (error()) {
        <p class="error-msg" role="alert">{{ error() }}</p>
      } @else if (items().length === 0) {
        <div class="empty-state"><p>{{ 'governance.catalog.assets.personalNone' | translate }}</p></div>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{{ 'governance.catalog.assets.attribute' | translate }}</th>
                <th scope="col">{{ 'governance.catalog.assets.sensitivity' | translate }}</th>
                <th scope="col">{{ 'governance.catalog.lineage' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (i of items(); track i.entity + '.' + i.attribute) {
                <tr [attr.data-attribute]="i.entity + '.' + i.attribute">
                  <td class="cell-mono">{{ i.entity }}.{{ i.attribute }}</td>
                  <td><span class="badge">{{ 'governance.catalog.assets.sensitivities.' + i.sensitivity | translate }}</span></td>
                  <td>
                    @if (i.readers.length === 0) {
                      {{ 'governance.common.none' | translate }}
                    } @else {
                      <ul>
                        @for (r of i.readers; track r.ref) {
                          <li>
                            {{ 'governance.catalog.lineageKinds.' + r.kind | translate }}: {{ r.label }}
                            @if (r.whole_entity) { {{ 'governance.catalog.wholeEntity' | translate }} }
                          </li>
                        }
                      </ul>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        @if (pages() > 1) {
          <nav class="gov-pager" [attr.aria-label]="'governance.common.pagination' | translate">
            <button type="button" class="btn-ghost" (click)="goToPage(page() - 1)" [disabled]="page() <= 1">
              {{ 'governance.common.previous' | translate }}
            </button>
            <span>{{ 'governance.common.pageOf' | translate: { page: page(), pages: pages() } }}</span>
            <button type="button" class="btn-ghost" (click)="goToPage(page() + 1)" [disabled]="page() >= pages()">
              {{ 'governance.common.next' | translate }}
            </button>
          </nav>
        }
      }
    </section>
  `,
})
export class PersonalDataMapComponent implements OnInit {
  private readonly svc = inject(DataCatalogService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly lang = inject(LangService);

  readonly pageSize = 50;
  readonly items = signal<PersonalDataItem[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly pages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));

  ngOnInit(): void {
    this.load();
  }

  goToPage(page: number): void {
    if (page < 1 || page > this.pages()) return;
    this.page.set(page);
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.personalDataMap(this.page(), this.pageSize).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => { this.items.set(res.items); this.total.set(res.total); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(this.lang.errorText(e)); this.loading.set(false); },
    });
  }
}
