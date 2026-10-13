import {
  ChangeDetectionStrategy, Component, OnDestroy, OnInit, computed, inject, input, signal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { forkJoin } from 'rxjs';
import { ApiError } from '@attome/base';

import { PageListItem, TargetListItem, WebcrawlAdminService } from '../../../services/webcrawl-admin.service';

type SelectionMode = 'single' | 'multiple';

/** How often a still-running crawl is re-read. The crawl job persists each
 *  page the moment it is fetched, so this cadence is what the operator sees
 *  as "pages appearing". */
const POLL_INTERVAL_MS = 2_000;
/** Ceiling on a single crawl's live view (~30 min at the interval above). A
 *  target wedged in `crawling` — a worker that died mid-walk, say — must not
 *  leave a browser tab polling forever; the view says so and offers a manual
 *  refresh rather than silently going stale. */
const MAX_POLLS = 900;
/** Consecutive poll failures tolerated before the live view gives up. A
 *  single blip (a redeploy, a dropped connection) should not kill it. */
const MAX_POLL_FAILURES = 3;

const RUNNING_STATUSES = ['pending', 'crawling'];

@Component({
  selector:   'attome-webcrawl-page-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, RouterLink],
  styleUrls:  ['../../../../styles/admin-page.css', '../../../webcrawl.css', './webcrawl-page-list.component.css'],
  templateUrl: './webcrawl-page-list.component.html',
})
export class WebcrawlPageListComponent implements OnInit, OnDestroy {
  /** Bound from the `:id` route param (Angular's `withComponentInputBinding`,
   *  matched by name) — absent on the bare `/xrm/admin/webcrawl/website`
   *  link, which auto-selects the most recently crawled target instead. */
  readonly id = input<string | null>(null);

  private readonly svc = inject(WebcrawlAdminService);

  readonly targets       = signal<TargetListItem[]>([]);
  readonly activeTargetId = signal<string | null>(null);
  readonly pages          = signal<PageListItem[]>([]);
  readonly loading        = signal(true);
  readonly error          = signal<string | null>(null);
  readonly selectionMode  = signal<SelectionMode>('single');
  readonly selected       = signal<Set<string>>(new Set());
  readonly importing      = signal(false);
  readonly importError    = signal<string | null>(null);
  /** A poll round-trip is in flight — drives the Refresh button only; it
   *  deliberately does not raise `loading()`, which would blank the table
   *  every two seconds. */
  readonly refreshing     = signal(false);
  readonly pollError      = signal<string | null>(null);
  readonly pollStalled    = signal(false);

  readonly activeTarget = computed(() =>
    this.targets().find(t => t.id === this.activeTargetId()) ?? null,
  );
  readonly isRunning = computed(() => {
    const status = this.activeTarget()?.status;
    return !!status && RUNNING_STATUSES.includes(status);
  });
  readonly crawledCount  = computed(() => this.pages().filter(p => p.status === 'crawled').length);
  readonly failedCount   = computed(() => this.pages().filter(p => p.status === 'failed').length);
  readonly importedCount = computed(() => this.pages().filter(p => !!p.imported_data_item_ref).length);

  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private pollsLeft = MAX_POLLS;
  private pollFailures = 0;

  ngOnInit(): void {
    this.svc.listTargets().subscribe({
      next: ts => {
        this.targets.set(ts);
        const initial = this.id() ?? ts[0]?.id ?? null;
        this.activeTargetId.set(initial);
        if (initial) this.refresh(true); else this.loading.set(false);
      },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  ngOnDestroy(): void { this.clearPoll(); }

  onSwitchTarget(id: string): void {
    this.clearPoll();
    this.activeTargetId.set(id);
    this.selected.set(new Set());
    this.pages.set([]);
    this.resetPollBudget();
    this.refresh(true);
  }

  refreshNow(): void {
    this.resetPollBudget();
    this.refresh(false);
  }

  onModeChange(mode: SelectionMode): void {
    this.selectionMode.set(mode);
    // Switching to single-select with more than one already checked would be
    // an inconsistent state to carry forward — clear rather than guess which one to keep.
    if (mode === 'single' && this.selected().size > 1) this.selected.set(new Set());
  }

  toggle(page: PageListItem): void {
    this.selected.update(sel => {
      const next = this.selectionMode() === 'single' ? new Set<string>() : new Set(sel);
      if (sel.has(page.id)) {
        next.delete(page.id);
      } else {
        next.add(page.id);
      }
      return next;
    });
  }

  importSelected(): void {
    const targetId = this.activeTargetId();
    const ids = [...this.selected()];
    if (!targetId || ids.length === 0) return;
    this.importing.set(true);
    this.importError.set(null);
    this.svc.importPages(targetId, ids).subscribe({
      next: () => {
        this.importing.set(false);
        this.selected.set(new Set());
        this.refresh(false);
      },
      error: (e: ApiError) => {
        this.importError.set(e.message);
        this.importing.set(false);
      },
    });
  }

  formatSize(bytes: number | null): string {
    if (bytes === null) return '—';
    return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  }

  /** One read of the active target's status plus its pages. The target list
   *  comes along because it carries the status/`last_error` this view shows
   *  (and there is no read-one-target route); it is one small page of rows. */
  private refresh(initial: boolean): void {
    const id = this.activeTargetId();
    if (!id) { this.loading.set(false); return; }
    if (initial) this.loading.set(true);
    this.refreshing.set(true);

    forkJoin({
      targets: this.svc.listTargets(),
      pages:   this.svc.listPages(id),
    }).subscribe({
      next: ({ targets, pages }) => {
        this.refreshing.set(false);
        // A target switch (or a destroy) can land between request and
        // response — dropping the stale answer keeps the two signals
        // describing the same website.
        if (this.activeTargetId() !== id) return;
        this.targets.set(targets);
        this.pages.set(pages);
        this.loading.set(false);
        this.error.set(null);
        this.pollError.set(null);
        this.pollFailures = 0;
        // A page that vanished (a recrawl replaces rows) must not stay in
        // the import selection.
        this.pruneSelection(pages);
        this.scheduleNextPoll();
      },
      error: (e: ApiError) => {
        this.refreshing.set(false);
        if (this.activeTargetId() !== id) return;
        this.loading.set(false);
        if (initial) {
          this.error.set(e.message);
          return;
        }
        this.pollFailures += 1;
        this.pollError.set(e.message);
        if (this.pollFailures < MAX_POLL_FAILURES) this.scheduleNextPoll();
      },
    });
  }

  /** Chained `setTimeout` rather than `setInterval`: the next read is only
   *  scheduled once the previous one has answered, so a slow response can
   *  never stack requests on top of each other. */
  private scheduleNextPoll(): void {
    this.clearPoll();
    if (!this.isRunning()) {
      this.resetPollBudget();
      return;
    }
    if (this.pollsLeft <= 0) {
      this.pollStalled.set(true);
      return;
    }
    this.pollsLeft -= 1;
    this.pollTimer = setTimeout(() => this.refresh(false), POLL_INTERVAL_MS);
  }

  private pruneSelection(pages: PageListItem[]): void {
    const importable = new Set(
      pages.filter(p => p.status === 'crawled' && !p.imported_data_item_ref).map(p => p.id),
    );
    this.selected.update(sel => {
      const next = new Set([...sel].filter(pageId => importable.has(pageId)));
      return next.size === sel.size ? sel : next;
    });
  }

  private resetPollBudget(): void {
    this.pollsLeft = MAX_POLLS;
    this.pollFailures = 0;
    this.pollStalled.set(false);
    this.pollError.set(null);
  }

  private clearPoll(): void {
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
  }
}
