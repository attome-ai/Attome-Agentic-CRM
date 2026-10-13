import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  DataQualityService, QUALITY_DIMENSIONS,
  type QualityDimension, type QualityIssue, type QualityIssueStatus, type QualityScore,
} from '@attome/xrm/core/admin/data';
import { GovernanceNavComponent } from '../nav/governance-nav.component';

/** One point of the trend line, already scaled into the SVG's box. */
interface TrendPoint { x: number; y: number; score: number; period: string; }

const TREND_WIDTH = 320;
const TREND_HEIGHT = 80;
const TREND_PAD = 6;

/**
 * U19 / M14 — the data-quality screen over `/api/v1/admin/data/quality*`:
 * the latest score per (entity, dimension), a trend for one pair, and the
 * steward's issue queue with a resolve action. Read-only apart from resolve;
 * the scores themselves are written by the nightly sweep
 * (`EngineJob::DataQualityScoreSweep`), never here.
 */
@Component({
  selector: 'xrm-data-quality',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, LocalNumberPipe, TranslatePipe, GovernanceNavComponent],
  styleUrls: ['../../../../styles/admin-page.css', '../governance.css', './data-quality.component.css'],
  templateUrl: './data-quality.component.html',
})
export class DataQualityComponent implements OnInit {
  private readonly svc = inject(DataQualityService);
  private readonly destroyRef = inject(DestroyRef);

  readonly dimensions = QUALITY_DIMENSIONS;
  readonly trendWidth = TREND_WIDTH;
  readonly trendHeight = TREND_HEIGHT;

  readonly entityFilter = signal('');

  readonly scores = signal<QualityScore[]>([]);
  readonly scoresLoading = signal(true);
  readonly scoresError = signal<string | null>(null);

  /** The (entity, dimension) whose trend is open, if any. */
  readonly trendKey = signal<{ entity: string; dimension: QualityDimension } | null>(null);
  readonly trend = signal<QualityScore[]>([]);
  readonly trendLoading = signal(false);
  readonly trendError = signal<string | null>(null);

  readonly issues = signal<QualityIssue[]>([]);
  readonly issuesTotal = signal(0);
  /** One-based (D-347). */
  readonly issuesPage = signal(1);
  readonly issuesPageSize = 50;
  readonly issueStatus = signal<QualityIssueStatus | ''>('open');
  readonly issueDimension = signal<QualityDimension | ''>('');
  readonly issuesLoading = signal(true);
  readonly issuesError = signal<string | null>(null);
  readonly resolvingId = signal<string | null>(null);
  /** Announced in a live region after a resolve attempt. */
  readonly notice = signal<string | null>(null);

  readonly issuesPages = computed(() => Math.max(1, Math.ceil(this.issuesTotal() / this.issuesPageSize)));

  /** Oldest -> newest, scaled into the SVG box (scores are 0-100). */
  readonly trendPoints = computed<TrendPoint[]>(() => {
    const series = [...this.trend()].reverse();
    if (series.length === 0) return [];
    const innerW = TREND_WIDTH - TREND_PAD * 2;
    const innerH = TREND_HEIGHT - TREND_PAD * 2;
    const step = series.length > 1 ? innerW / (series.length - 1) : 0;
    return series.map((s, i) => ({
      x: TREND_PAD + (series.length > 1 ? i * step : innerW / 2),
      y: TREND_PAD + innerH - (Math.min(100, Math.max(0, s.score)) / 100) * innerH,
      score: s.score,
      period: s.period,
    }));
  });

  readonly trendPath = computed(() =>
    this.trendPoints().map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' '));

  ngOnInit(): void {
    this.loadScores();
    this.loadIssues();
  }

  refresh(): void {
    this.trendKey.set(null);
    this.issuesPage.set(1);
    this.loadScores();
    this.loadIssues();
  }

  loadScores(): void {
    this.scoresLoading.set(true);
    this.scoresError.set(null);
    this.svc.listScores(this.entity()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: items => { this.scores.set(items); this.scoresLoading.set(false); },
      error: (e: ApiError) => { this.scoresError.set(e.message); this.scoresLoading.set(false); },
    });
  }

  loadIssues(): void {
    this.issuesLoading.set(true);
    this.issuesError.set(null);
    this.svc.listIssues({
      entity: this.entity(),
      status: this.issueStatus() || undefined,
      dimension: this.issueDimension() || undefined,
    }, this.issuesPage(), this.issuesPageSize).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        this.issues.set(res.items);
        this.issuesTotal.set(res.total);
        this.issuesLoading.set(false);
      },
      error: (e: ApiError) => { this.issuesError.set(e.message); this.issuesLoading.set(false); },
    });
  }

  setIssueStatus(value: QualityIssueStatus | ''): void {
    this.issueStatus.set(value);
    this.issuesPage.set(1);
    this.loadIssues();
  }

  setIssueDimension(value: QualityDimension | ''): void {
    this.issueDimension.set(value);
    this.issuesPage.set(1);
    this.loadIssues();
  }

  goToIssuesPage(page: number): void {
    if (page < 1 || page > this.issuesPages()) return;
    this.issuesPage.set(page);
    this.loadIssues();
  }

  isTrendOpen(s: QualityScore): boolean {
    const k = this.trendKey();
    return !!k && k.entity === s.entity_logicalname && k.dimension === s.dimension;
  }

  toggleTrend(s: QualityScore): void {
    if (this.isTrendOpen(s)) { this.trendKey.set(null); return; }
    const dimension = s.dimension as QualityDimension;
    this.trendKey.set({ entity: s.entity_logicalname, dimension });
    this.trend.set([]);
    this.trendLoading.set(true);
    this.trendError.set(null);
    this.svc.scoreHistory(s.entity_logicalname, dimension).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => { this.trend.set(res.items); this.trendLoading.set(false); },
      error: (e: ApiError) => { this.trendError.set(e.message); this.trendLoading.set(false); },
    });
  }

  resolve(issue: QualityIssue): void {
    this.resolvingId.set(issue.id);
    this.notice.set(null);
    this.svc.resolveIssue(issue.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.resolvingId.set(null);
        this.notice.set('governance.quality.resolvedNotice');
        this.loadIssues();
      },
      error: (e: ApiError) => {
        this.resolvingId.set(null);
        // 409: someone (or the same steward in another tab) already resolved
        // it — say so and refresh rather than showing a raw error.
        if (e.status === 409) {
          this.notice.set('governance.quality.alreadyResolved');
          this.loadIssues();
        } else {
          this.issuesError.set(e.message);
        }
      },
    });
  }

  /** Score band for colouring the bar: good / fair / poor. */
  band(score: number): 'good' | 'fair' | 'poor' {
    if (score >= 90) return 'good';
    if (score >= 70) return 'fair';
    return 'poor';
  }

  private entity(): string | undefined {
    return this.entityFilter().trim() || undefined;
  }
}
