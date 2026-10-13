import { DatePipe, DecimalPipe, DOCUMENT } from '@angular/common';
import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiError } from '@attome/base';
import {
  EMPTY, Observable, distinctUntilChanged, fromEvent, interval, map, startWith, switchMap,
} from 'rxjs';

import { ApiGroup, ProfilerAdminService, StatRow, TraceSample } from '../services/profiler-admin.service';

/** The refresh cadence while the tab is visible. Exported for the spec. */
export const POLL_INTERVAL_MS = 3000;

/** Which layer of the server a probe measures, from its dotted name. */
export type ProbeCategory = 'loading' | 'job' | 'request';

/**
 * Classifies a probe name. `boot` (and its `boot.*` sub-parts) is the loading
 * timeline `crates/server/src/boot.rs` flushes once per boot; `job.*` (from
 * `handle_platform_job`) is queued background work; everything else is request traffic (the
 * automatic `"{METHOD} {route}"` total plus any `measure!` a handler placed).
 */
export function categoryOf(name: string): ProbeCategory {
  if (name === 'boot' || name.startsWith('boot.')) { return 'loading'; }
  if (name === 'job' || name.startsWith('job.')) { return 'job'; }
  return 'request';
}

/** One row of the "slowest probes" leaderboard. */
export interface SlowRow {
  name: string;
  category: ProbeCategory;
  count: number;
  total_ms: number;
  avg_ms: number;
  min_ms: number;
  max_ms: number;
  /** Share of all measured probe time (0-100). */
  share: number;
}

export type SortDirection = 'asc' | 'desc';

/** Columns the "all probes" table can be sorted by. */
export type MainSortKey = 'name' | 'count' | 'avg_ms' | 'min_ms' | 'max_ms' | 'total_ms';

/** Columns the "slowest probes" leaderboard can be sorted by. `share` sorts by `total_ms` — it is a fixed multiple of it for a given snapshot. */
export type SlowSortKey = 'name' | 'category' | 'count' | 'avg_ms' | 'min_ms' | 'max_ms' | 'total_ms' | 'share';

function compareValues(a: string | number, b: string | number): number {
  if (typeof a === 'string' || typeof b === 'string') { return String(a).localeCompare(String(b)); }
  return a - b;
}

/** Ascending is the natural default for names/categories; every numeric metric defaults to descending (biggest first). */
function defaultDirectionFor(col: string): SortDirection {
  return col === 'name' || col === 'category' ? 'asc' : 'desc';
}

/** One phase of the `boot` loading timeline. */
export interface BootPhaseRow {
  name: string;
  count: number;
  total_ms: number;
  /** Share of the whole boot (0-100). */
  pct: number;
}

/** Total measured time per category, for the summary strip. */
export interface ProfileSummary {
  loading_ms: number;
  request_ms: number;
  job_ms: number;
  total_ms: number;
}

function toSlowRow(r: StatRow): Omit<SlowRow, 'share'> {
  return {
    name: r.name,
    category: categoryOf(r.name),
    count: r.count,
    total_ms: r.total_ms,
    avg_ms: r.avg_ms,
    min_ms: r.min_ms,
    max_ms: r.max_ms,
  };
}

function clampPct(value: number): number {
  return Math.max(0, Math.min(100, value));
}

/**
 * Whether the document is currently visible, as a stream - current state on
 * subscribe, then every change, deduplicated.
 *
 * A deliberate duplicate of `pageVisible$` in
 * `@attome/xrm/shell`'s `notification-bell.component.ts`, which is the
 * canonical copy: this entry point cannot reach it without importing the
 * shell barrel, which would flatten the whole shell into the profiler chunk
 * (D-314). If a third caller appears, lift the helper into `@attome/base` and
 * delete both copies.
 */
function pageVisible$(doc: Document): Observable<boolean> {
  return fromEvent(doc, 'visibilitychange').pipe(
    startWith(null),
    map(() => doc.visibilityState === 'visible'),
    distinctUntilChanged(),
  );
}

@Component({
  selector:   'xrm-profiler',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [DatePipe, DecimalPipe],
  styleUrls:  ['../../../styles/admin-page.css', './profiler.component.css'],
  templateUrl: './profiler.component.html',
})
export class ProfilerComponent implements OnInit {
  private readonly svc        = inject(ProfilerAdminService);
  private readonly document   = inject(DOCUMENT);
  private readonly destroyRef = inject(DestroyRef);

  readonly groups       = signal<ApiGroup[]>([]);
  readonly loading      = signal(true);
  readonly error        = signal<string | null>(null);
  readonly lastUpdated  = signal<Date | null>(null);
  private readonly expanded = signal<Set<string>>(new Set());

  readonly waterfallFor      = signal<string | null>(null);
  readonly waterfallLoading  = signal(false);
  readonly waterfallSamples  = signal<TraceSample[]>([]);

  readonly mainSortColumn    = signal<MainSortKey>('total_ms');
  readonly mainSortDirection = signal<SortDirection>('desc');

  /** Top-level probes, sorted by the current column/direction — total time descending by default, so the page opens on what costs. */
  readonly sortedGroups = computed(() => {
    const col = this.mainSortColumn();
    const dir = this.mainSortDirection() === 'asc' ? 1 : -1;
    return this.groups().slice().sort((a, b) => dir * compareValues(a.api[col], b.api[col]));
  });

  /** Loading vs request vs job time - where the server's time goes, at a glance. */
  readonly summary = computed<ProfileSummary>(() => {
    let loading_ms = 0;
    let request_ms = 0;
    let job_ms = 0;
    for (const g of this.groups()) {
      const ms = g.api.total_ms;
      switch (categoryOf(g.api.name)) {
        case 'loading': loading_ms += ms; break;
        case 'job':     job_ms += ms;     break;
        default:        request_ms += ms;
      }
    }
    return { loading_ms, request_ms, job_ms, total_ms: loading_ms + request_ms + job_ms };
  });

  readonly slowSortColumn    = signal<SlowSortKey>('total_ms');
  readonly slowSortDirection = signal<SortDirection>('desc');

  /**
   * The top 12 probes by total time, then re-ordered by whichever column the
   * user picked. The leaderboard membership always stays "biggest total
   * consumers" — sorting only changes how those 12 are ordered.
   */
  readonly slowest = computed<SlowRow[]>(() => {
    const total = this.summary().total_ms || 1;
    const top = this.groups()
      .map(g => toSlowRow(g.api))
      .filter(r => r.total_ms > 0)
      .sort((a, b) => b.total_ms - a.total_ms)
      .slice(0, 12)
      .map(r => ({ ...r, share: clampPct((r.total_ms / total) * 100) }));

    const col = this.slowSortColumn();
    const key: keyof SlowRow = col === 'share' ? 'total_ms' : col;
    const dir = this.slowSortDirection() === 'asc' ? 1 : -1;
    return top.sort((a, b) => dir * compareValues(a[key], b[key]));
  });

  /** The `boot` loading flush, when this node has booted with the profiler on. */
  readonly bootGroup   = computed(() => this.groups().find(g => g.api.name === 'boot') ?? null);
  readonly bootTotalMs = computed(() => this.bootGroup()?.api.total_ms ?? 0);

  /** The boot's phases, slowest first, as a share of the whole loading time. */
  readonly bootPhases = computed<BootPhaseRow[]>(() => {
    const group = this.bootGroup();
    if (!group) { return []; }
    const total = group.api.total_ms || 1;
    return group.parts
      .slice()
      .sort((a, b) => b.total_ms - a.total_ms)
      .map(p => ({
        name: p.name.replace(/^boot\./, ''),
        count: p.count,
        total_ms: p.total_ms,
        pct: clampPct((p.total_ms / total) * 100),
      }));
  });

  ngOnInit(): void {
    // A 3 s poll from a background tab is 1,200 requests an hour that nobody
    // sees (T7-4): tick only while the document is visible, and refresh at
    // once when it becomes visible again. `startWith` rather than
    // `timer(0, ...)` so that first refresh is synchronous - the same
    // first-paint behaviour the old `refresh()` call in `ngOnInit` had.
    pageVisible$(this.document).pipe(
      switchMap(visible => visible ? interval(POLL_INTERVAL_MS).pipe(startWith(0)) : EMPTY),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe(() => this.refresh());
  }

  refresh(): void {
    this.loading.set(true);
    this.svc.stats().subscribe({
      next: gs => {
        this.groups.set(gs);
        this.loading.set(false);
        this.error.set(null);
        this.lastUpdated.set(new Date());
      },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  toggleMainSort(col: MainSortKey): void {
    if (this.mainSortColumn() === col) {
      this.mainSortDirection.update(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      this.mainSortColumn.set(col);
      this.mainSortDirection.set(defaultDirectionFor(col));
    }
  }

  isMainSortedBy(col: MainSortKey): boolean { return this.mainSortColumn() === col; }

  mainSortIcon(col: MainSortKey): string {
    if (!this.isMainSortedBy(col)) { return 'las la-sort'; }
    return this.mainSortDirection() === 'asc' ? 'las la-sort-up' : 'las la-sort-down';
  }

  toggleSlowSort(col: SlowSortKey): void {
    if (this.slowSortColumn() === col) {
      this.slowSortDirection.update(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      this.slowSortColumn.set(col);
      this.slowSortDirection.set(defaultDirectionFor(col));
    }
  }

  isSlowSortedBy(col: SlowSortKey): boolean {
    const current = this.slowSortColumn();
    return current === col || (col === 'share' && current === 'total_ms') || (col === 'total_ms' && current === 'share');
  }

  slowSortIcon(col: SlowSortKey): string {
    if (!this.isSlowSortedBy(col)) { return 'las la-sort'; }
    return this.slowSortDirection() === 'asc' ? 'las la-sort-up' : 'las la-sort-down';
  }

  isExpanded(name: string): boolean { return this.expanded().has(name); }

  toggleExpand(name: string): void {
    const next = new Set(this.expanded());
    if (next.has(name)) { next.delete(name); } else { next.add(name); }
    this.expanded.set(next);
  }

  showWaterfall(name: string): void {
    this.waterfallFor.set(name);
    this.waterfallLoading.set(true);
    this.svc.trace(name, 10).subscribe({
      next: samples => { this.waterfallSamples.set(samples); this.waterfallLoading.set(false); },
      error: () => { this.waterfallSamples.set([]); this.waterfallLoading.set(false); },
    });
  }

  closeWaterfall(): void {
    this.waterfallFor.set(null);
    this.waterfallSamples.set([]);
  }

  segmentWidth(part: { ms: number }, sample: TraceSample): number {
    if (sample.total_ms <= 0) { return 0; }
    return Math.min(100, (part.ms / sample.total_ms) * 100);
  }

  formatTotal(totalMs: number): string {
    if (totalMs < 1000) { return `${totalMs.toFixed(1)} ms`; }
    const seconds = totalMs / 1000;
    if (seconds < 60) { return `${seconds.toFixed(1)} s`; }
    const minutes = seconds / 60;
    return `${minutes.toFixed(1)} min`;
  }
}
