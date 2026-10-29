import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { forkJoin, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { TranslatePipe } from '@attome/base';
import { DashboardService, ScorecardItem, ScorecardRead } from '@attome/xrm/dashboard/data';
import { TargetSpreadDialogComponent } from '../target-spread-dialog/target-spread-dialog.component';

/** The band a snapshot status draws in. Pure. */
export function statusBand(status: string | null): 'good' | 'warn' | 'bad' | 'none' {
  switch (status) {
    case 'on_track': return 'good';
    case 'at_risk': return 'warn';
    case 'off_track':
    case 'failed': return 'bad';
    default: return 'none';
  }
}

/** The freshness badge a row shows, if any. Pure. */
export function freshnessBadge(item: ScorecardItem): 'failed' | 'stale' | null {
  if (item.freshness.failed) return 'failed';
  if (item.freshness.is_stale) return 'stale';
  return null;
}

/**
 * P9-T15: a scorecard (`?id=`): one row per metric with its newest stored
 * value, the period's target, the status band, a stale or failed badge and
 * the period's latest comment; a target can be spread from a row.
 */
@Component({
  selector: 'attome-metric-scorecard',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, TargetSpreadDialogComponent],
  templateUrl: './metric-scorecard.component.html',
  styleUrls: ['./metric-scorecard.component.css'],
})
export class MetricScorecardComponent implements OnInit {
  private readonly svc = inject(DashboardService);

  readonly id = input<string | null>(null);
  readonly scorecard = signal<ScorecardRead | null>(null);
  readonly comments = signal<Record<string, string>>({});
  readonly loading = signal(true);
  readonly failed = signal(false);
  /** The row whose target is being spread. */
  readonly spreading = signal<ScorecardItem | null>(null);

  readonly band = statusBand;
  readonly badge = freshnessBadge;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    const id = this.id();
    if (!id) {
      this.loading.set(false);
      this.failed.set(true);
      return;
    }
    this.loading.set(true);
    this.svc.getScorecard(id).subscribe({
      next: card => {
        this.scorecard.set(card);
        this.loading.set(false);
        this.loadComments(card.items);
      },
      error: () => {
        this.loading.set(false);
        this.failed.set(true);
      },
    });
  }

  /** Each row's newest comment on its period; a row whose comments cannot
   * be read shows none. */
  private loadComments(items: ScorecardItem[]): void {
    const withPeriod = items.filter(i => i.period_start);
    if (withPeriod.length === 0) return;
    forkJoin(withPeriod.map(i =>
      this.svc.listComments(i.metric_id, i.period_start).pipe(
        map(page => [i.metric_id, page.items[0]?.body ?? ''] as const),
        catchError(() => of([i.metric_id, ''] as const)),
      ),
    )).subscribe(pairs => {
      const out: Record<string, string> = {};
      for (const [id, body] of pairs) if (body) out[id] = body;
      this.comments.set(out);
    });
  }

  spreadClosed(saved: unknown): void {
    this.spreading.set(null);
    if (saved) this.load();
  }
}
