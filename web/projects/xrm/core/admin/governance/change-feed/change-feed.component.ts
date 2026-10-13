import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  CHANGE_KINDS, ChangeFeedService,
  type ChangeFeedEntry, type ChangeFeedFilter, type ChangeKind,
} from '@attome/xrm/core/admin/data';
import { GovernanceNavComponent } from '../nav/governance-nav.component';

/**
 * `<input type="date">` value (`YYYY-MM-DD`, the viewer's calendar day) to
 * the ISO instant the route expects. `endOfDay` makes the upper bound
 * inclusive of the whole chosen day.
 */
export function dateInputToIso(value: string, endOfDay: boolean): string | undefined {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!m) return undefined;
  const d = endOfDay
    ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 59, 999)
    : new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 0, 0, 0, 0);
  return d.toISOString();
}

/**
 * U19 / M89 — the change feed over `GET /api/v1/admin/changes`: metadata,
 * bundle, query/workflow/dashboard/content publishes, licence, security
 * grant, AI model and settings changes merged newest-first.
 *
 * Keyset paged (see `ChangeFeedService`): "Next" follows the page's
 * `next_cursor`, "Previous" pops a stack of the cursors that led here. The
 * filter is resolved once per Apply — an empty "To" is pinned to that
 * moment — so every page reads the same window and the first page's exact
 * `total` stays true while paging.
 */
@Component({
  selector: 'xrm-change-feed',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, LocalNumberPipe, TranslatePipe, GovernanceNavComponent],
  styleUrls: ['../../../../styles/admin-page.css', '../governance.css', './change-feed.component.css'],
  templateUrl: './change-feed.component.html',
})
export class ChangeFeedComponent implements OnInit {
  private readonly svc = inject(ChangeFeedService);
  private readonly destroyRef = inject(DestroyRef);

  readonly kinds = CHANGE_KINDS;

  readonly kind = signal<ChangeKind | ''>('');
  /** `YYYY-MM-DD`, empty for the server default (the last 30 days). */
  readonly from = signal('');
  readonly to = signal('');

  readonly items = signal<ChangeFeedEntry[]>([]);
  /** Exact count for the applied window, from its first page. */
  readonly total = signal(0);
  readonly pageSize = 50;
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  /** The window every page of the current listing reads. */
  private filter: ChangeFeedFilter = {};
  /** Cursor of each visited page; `undefined` is the first page. */
  private readonly cursors = signal<(string | undefined)[]>([undefined]);
  private readonly nextCursor = signal<string | null>(null);

  /** One-based position of the page on screen. */
  readonly page = computed(() => this.cursors().length);
  readonly pages = computed(() => Math.max(this.page(), Math.ceil(this.total() / this.pageSize)));
  readonly hasPrevious = computed(() => this.page() > 1);
  readonly hasNext = computed(() => this.nextCursor() !== null);

  ngOnInit(): void { this.apply(); }

  apply(): void {
    this.filter = {
      kind: this.kind() || undefined,
      from: dateInputToIso(this.from(), false),
      to: dateInputToIso(this.to(), true) ?? new Date().toISOString(),
    };
    this.cursors.set([undefined]);
    this.load();
  }

  reset(): void {
    this.kind.set('');
    this.from.set('');
    this.to.set('');
    this.apply();
  }

  next(): void {
    const cursor = this.nextCursor();
    if (cursor === null || this.loading()) return;
    this.cursors.update(stack => [...stack, cursor]);
    this.load();
  }

  previous(): void {
    if (!this.hasPrevious() || this.loading()) return;
    this.cursors.update(stack => stack.slice(0, -1));
    this.load();
  }

  private load(): void {
    const stack = this.cursors();
    this.loading.set(true);
    this.error.set(null);
    this.svc.listChanges(this.filter, stack[stack.length - 1], this.pageSize)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: res => {
          this.items.set(res.items);
          if (res.total !== null && res.total !== undefined) this.total.set(res.total);
          this.nextCursor.set(res.next_cursor ?? null);
          this.loading.set(false);
        },
        error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
      });
  }
}
