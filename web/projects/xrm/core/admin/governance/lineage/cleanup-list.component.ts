import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, inject, output, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { LineageService, type LineageCleanup } from '@attome/xrm/core/admin/data';

/**
 * L5-T7: what needs tidying in the lineage graph (`GET /api/v1/lineage/cleanup`,
 * administrators): edges to an entity or attribute that no longer exists,
 * definitions that depend on themselves through others, and attributes no
 * definition uses. Choosing an item walks from it (`open`).
 */
@Component({
  selector: 'xrm-lineage-cleanup',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../governance.css', './lineage.component.css'],
  template: `
    <section class="card" aria-labelledby="lc-title" data-cleanup>
      <h3 id="lc-title">{{ 'governance.lineage.cleanup.title' | translate }}</h3>
      @if (loading()) {
        <p class="state-msg">{{ 'governance.common.loading' | translate }}</p>
      } @else if (error(); as e) {
        <p class="error-msg" role="alert">{{ e }}</p>
      } @else if (cleanup(); as c) {
        @if (c.dangling.length === 0 && c.cycles.length === 0 && c.unused_attributes.length === 0) {
          <p class="gov-muted" data-cleanup-clean>{{ 'governance.lineage.cleanup.clean' | translate }}</p>
        }
        @if (c.dangling.length > 0) {
          <h4>{{ 'governance.lineage.cleanup.dangling' | translate }} <span class="count">{{ c.dangling.length }}</span></h4>
          <ul class="lc-list" data-cleanup-dangling>
            @for (e of c.dangling; track e.from + e.to + e.edge_kind) {
              <li>
                <button type="button" class="btn-text cell-mono" dir="ltr" (click)="open.emit(e.from)">{{ e.from }}</button>
                <span aria-hidden="true">→</span>
                <span class="cell-mono lc-gone" dir="ltr">{{ e.to }}</span>
              </li>
            }
          </ul>
        }
        @if (c.cycles.length > 0) {
          <h4>{{ 'governance.lineage.cleanup.cycles' | translate }} <span class="count">{{ c.cycles.length }}</span></h4>
          <ul class="lc-list" data-cleanup-cycles>
            @for (cycle of c.cycles; track $index) {
              <li class="cell-mono" dir="ltr">{{ cycle.join(' → ') }}</li>
            }
          </ul>
        }
        @if (c.unused_attributes.length > 0) {
          <h4>{{ 'governance.lineage.cleanup.unused' | translate }} <span class="count">{{ c.unused_attributes.length }}</span></h4>
          <ul class="lc-list lc-list--inline" data-cleanup-unused>
            @for (a of c.unused_attributes; track a) {
              <li><button type="button" class="btn-text cell-mono" dir="ltr" (click)="open.emit('entity:' + a)">{{ a }}</button></li>
            }
          </ul>
        }
      }
    </section>
  `,
})
export class CleanupListComponent implements OnInit {
  private readonly svc = inject(LineageService);
  private readonly destroyRef = inject(DestroyRef);

  /** A node key to walk from. */
  readonly open = output<string>();

  readonly cleanup = signal<LineageCleanup | null>(null);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.svc.cleanup().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: c => { this.cleanup.set(c); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }
}
