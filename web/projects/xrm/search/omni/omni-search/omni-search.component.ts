import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { TranslatePipe } from '@attome/base';
import { Subject, debounceTime, distinctUntilChanged, filter, switchMap } from 'rxjs';
import { catchError, map, of } from 'rxjs';
import {
  HitGroup,
  SearchHit,
  SearchService,
  formatTotal,
  groupHits,
  isRelaxed,
} from '../search.service';

/** Everything a later interaction report (TODO-021) needs, captured as it happens. */
export interface OmniSelection {
  hit: SearchHit;
  /** Rank in the flat result list, 0-based. */
  rank: number;
  /** The impression this selection belongs to, or `null` if none was logged. */
  impressionId: string | null;
}

/** Debounce window. Inside the 150–250 ms the plan specifies. */
export const DEBOUNCE_MS = 200;
/** Below this, a query matches most of the corpus and costs a round trip to say so. */
export const MIN_QUERY_LENGTH = 2;

/**
 * The omni-search box (TODO-026).
 *
 * ## The three things that are load-bearing
 *
 * **`switchMap`, not `mergeMap`.** Every keystroke cancels the in-flight
 * request. With `mergeMap` a slow response for "ac" can arrive *after* the fast
 * one for "acme" and overwrite correct results with stale ones — the classic
 * typeahead bug, which is invisible on a fast network and constant on a slow
 * one, so it reliably survives development and ships.
 *
 * **The result set says when it is approximate.** Two separate signals:
 * `relaxed()` when every hit came from fuzzy matching alone, and the total,
 * which renders `at_least` as "500+" and never as a bare number. A user who
 * typed a name and got a near match with no marker will read it as exact and
 * act on the wrong record.
 *
 * **`degraded[]` is shown, never swallowed.** A result set silently missing a
 * leg looks exactly like "no more matches", which is indistinguishable from a
 * correct empty answer — the backend goes to real trouble to report it and
 * dropping it here would waste that entirely.
 *
 * ## No highlighting
 *
 * `ts_headline` is deliberately not requested. It re-parses and re-ranks every
 * returned document server-side; that is affordable on a results page and not
 * on a keystroke.
 *
 * ## Accessibility
 *
 * The WAI-ARIA combobox pattern, because a search box that only works with a
 * mouse is one a keyboard user cannot use at all: `role="combobox"` with
 * `aria-expanded`/`aria-controls`/`aria-activedescendant` on the input, a
 * `listbox` of `option`s, arrow keys that move the active option **without
 * moving focus out of the input**, Enter to select, Escape to close. The
 * results region is `aria-live="polite"` so a screen reader hears the count
 * change without being interrupted mid-word on every keystroke.
 */
@Component({
  selector: 'xrm-omni-search',
  standalone: true,
  imports: [TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./omni-search.component.css'],
  templateUrl: './omni-search.component.html',
})
export class OmniSearchComponent {
  private readonly service = inject(SearchService);
  private readonly destroyRef = inject(DestroyRef);

  readonly placeholder = input('Search');
  readonly label = input('Search records');
  readonly pageSize = input(10);

  readonly selected = output<OmniSelection>();

  readonly query = signal('');
  readonly searching = signal(false);
  readonly open = signal(false);
  /** Index into `flat()` of the active option, or -1 for none. */
  readonly active = signal(-1);
  readonly flat = signal<SearchHit[]>([]);
  readonly degraded = signal<string[]>([]);
  readonly totalLabel = signal('');
  private readonly impressionId = signal<string | null>(null);

  readonly groups = computed<HitGroup[]>(() => groupHits(this.flat()));
  readonly relaxed = computed(() => isRelaxed(this.flat()));
  readonly activeId = computed(() => (this.active() >= 0 ? `omni-opt-${this.active()}` : null));

  private readonly typed = new Subject<string>();

  constructor() {
    this.typed
      .pipe(
        debounceTime(DEBOUNCE_MS),
        distinctUntilChanged(),
        filter((q) => q.trim().length >= MIN_QUERY_LENGTH),
        // switchMap, deliberately — see the class doc. Every keystroke cancels
        // the in-flight request, so a slow response for a shorter prefix can
        // never overwrite the results for what the user has actually typed.
        switchMap((q) => {
          this.searching.set(true);
          return this.service.search(q, { pageSize: this.pageSize() }).pipe(
            // An error empties the list rather than leaving the previous
            // query's hits on screen under the new query's text — stale
            // results the user believes are current are worse than none.
            catchError(() => of(null)),
            map((response) => response),
          );
        }),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe((response) => {
        this.searching.set(false);
        if (!response) {
          this.flat.set([]);
          this.degraded.set([]);
          this.totalLabel.set('');
          this.impressionId.set(null);
          return;
        }
        this.flat.set(response.items ?? []);
        this.degraded.set(response.degraded ?? []);
        this.totalLabel.set(formatTotal(response.total));
        this.impressionId.set(response.impression_id ?? null);
        this.active.set(-1);
        this.open.set(true);
      });
  }

  onInput(value: string): void {
    this.query.set(value);
    if (value.trim().length < MIN_QUERY_LENGTH) {
      // Closing here rather than waiting for an empty response: clearing the
      // box must clear the panel immediately, not one debounce later.
      this.open.set(false);
      this.flat.set([]);
      this.searching.set(false);
    }
    this.typed.next(value);
  }

  onKeydown(event: KeyboardEvent): void {
    const count = this.flat().length;
    switch (event.key) {
      case 'ArrowDown':
        if (!this.open() || count === 0) return;
        event.preventDefault();
        this.active.set((this.active() + 1) % count);
        return;
      case 'ArrowUp':
        if (!this.open() || count === 0) return;
        event.preventDefault();
        this.active.set(this.active() <= 0 ? count - 1 : this.active() - 1);
        return;
      case 'Enter': {
        const hit = this.flat()[this.active()];
        if (!hit) return;
        event.preventDefault();
        this.select(hit);
        return;
      }
      case 'Escape':
        this.open.set(false);
        this.active.set(-1);
        return;
      default:
    }
  }

  rankOf(hit: SearchHit): number {
    return this.flat().indexOf(hit);
  }

  /**
   * Emits the selection with everything a later interaction report needs.
   *
   * It is not posted anywhere yet: TODO-021's interaction route does not exist,
   * and calling an endpoint that 404s would put a permanent error in every
   * user's console. The rank and impression id are captured *here* rather than
   * reconstructed later, because after the panel closes neither is recoverable.
   */
  select(hit: SearchHit): void {
    this.selected.emit({
      hit,
      rank: this.rankOf(hit),
      impressionId: this.impressionId(),
    });
    this.open.set(false);
    this.active.set(-1);
  }
}
