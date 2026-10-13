import {
  ChangeDetectionStrategy, Component, OnDestroy, OnInit, computed, inject, signal,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ApiError, TranslatePipe } from '@attome/base';

import { TargetListItem, WebcrawlAdminService } from '../../../services/webcrawl-admin.service';

/** Matches the detail page's cadence — see webcrawl-page-list.component.ts. */
const POLL_INTERVAL_MS = 2_000;
const MAX_POLLS = 900;

const RUNNING_STATUSES = ['pending', 'crawling'];

@Component({
  selector:   'attome-webcrawl-target-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, RouterLink, DatePipe, TranslatePipe],
  styleUrls:  ['../../../../styles/admin-page.css', '../../../webcrawl.css', './webcrawl-target-list.component.css'],
  templateUrl: './webcrawl-target-list.component.html',
})
export class WebcrawlTargetListComponent implements OnInit, OnDestroy {
  private readonly svc    = inject(WebcrawlAdminService);
  private readonly router = inject(Router);

  readonly targets    = signal<TargetListItem[]>([]);
  readonly loading    = signal(true);
  readonly error      = signal<string | null>(null);
  readonly urlInput   = signal('');
  /** Matches the backend default (`config.webcrawl.max_depth`). The API
   *  itself accepts up to `attome_webcrawl::model::MAX_DEPTH` (20); this
   *  dropdown offers the range that's actually useful to pick from. */
  readonly depthOptions = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  readonly depthInput   = signal(6);
  readonly starting   = signal(false);
  readonly formError  = signal<string | null>(null);

  /** True while at least one target is still queued or being walked — the
   *  only condition under which this list keeps re-reading itself. */
  readonly anyRunning = computed(() => this.targets().some(t => this.isRunning(t)));

  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private pollsLeft = MAX_POLLS;

  ngOnInit(): void { this.load(); }

  ngOnDestroy(): void { this.clearPoll(); }

  isRunning(t: TargetListItem): boolean { return RUNNING_STATUSES.includes(t.status); }

  private load(): void {
    this.loading.set(true);
    this.svc.listTargets().subscribe({
      next:  ts => { this.targets.set(ts); this.loading.set(false); this.scheduleNextPoll(); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  startCrawling(): void {
    const url = this.urlInput().trim();
    if (!url) return;
    this.starting.set(true);
    this.formError.set(null);
    this.svc.createTarget(url, this.depthInput()).subscribe({
      next: t => {
        // A resubmitted URL comes back as the same id (the backend treats it
        // as a recrawl, not a new row) — replace it in place rather than
        // adding a duplicate; a genuinely new URL is prepended.
        this.targets.update(ts => {
          const existing = ts.some(x => x.id === t.id);
          return existing ? ts.map(x => x.id === t.id ? t : x) : [t, ...ts];
        });
        this.urlInput.set('');
        this.starting.set(false);
        // The crawl is already enqueued and writes pages as it walks, so the
        // detail page is where there is something to watch — go straight
        // there rather than leaving the operator on a row that says
        // "pending".
        void this.router.navigate(['/xrm/admin/webcrawl/targets', t.id]);
      },
      error: (e: ApiError) => {
        this.formError.set(e.message);
        this.starting.set(false);
      },
    });
  }

  recrawl(t: TargetListItem): void {
    this.svc.recrawlTarget(t.id).subscribe({
      next: updated => {
        this.targets.update(ts => ts.map(x => x.id === updated.id ? updated : x));
        this.pollsLeft = MAX_POLLS;
        this.scheduleNextPoll();
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  remove(t: TargetListItem): void {
    if (!confirm(`Delete the crawl of "${t.url}"? This removes its crawled pages too.`)) return;
    this.svc.deleteTarget(t.id).subscribe({
      next:  () => this.targets.update(ts => ts.filter(x => x.id !== t.id)),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** Chained `setTimeout`, not `setInterval`: the next read only goes out
   *  once the previous one answered, so slow responses cannot stack up. */
  private scheduleNextPoll(): void {
    this.clearPoll();
    if (!this.anyRunning()) {
      this.pollsLeft = MAX_POLLS;
      return;
    }
    if (this.pollsLeft <= 0) return;
    this.pollsLeft -= 1;
    this.pollTimer = setTimeout(() => this.pollOnce(), POLL_INTERVAL_MS);
  }

  private pollOnce(): void {
    this.svc.listTargets().subscribe({
      // A background refresh must never blank the table or replace it with an
      // error banner — a blip just costs one tick and the loop carries on.
      next:  ts => { this.targets.set(ts); this.scheduleNextPoll(); },
      error: () => this.scheduleNextPoll(),
    });
  }

  private clearPoll(): void {
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
  }
}
