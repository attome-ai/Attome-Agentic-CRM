import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  DataQualityService, QUALITY_DIMENSIONS, QUALITY_ISSUE_STATUSES, SCORE_DIMENSIONS,
  type QualityDimension, type QualityIssue, type QualityIssueStatus, type QualityScore,
  type QualityTarget,
} from '@attome/xrm/core/admin/data';
import { GovernanceNavComponent } from '../nav/governance-nav.component';
import { QualityFixesComponent } from './quality-fixes.component';
import { QualityRulesComponent } from './quality-rules.component';

/** L2-T8: the screen's tabs. */
export const QUALITY_TABS = ['overview', 'rules', 'issues', 'fixes'] as const;
export type QualityTab = typeof QUALITY_TABS[number];

/** One dimension's card: the mean of its latest score over the entities. */
export interface DimensionCard { dimension: string; score: number; entities: number; }

/** One point of the trend line, already scaled into the SVG's box. */
interface TrendPoint { x: number; y: number; score: number; period: string; }

const TREND_WIDTH = 320;
const TREND_HEIGHT = 80;
const TREND_PAD = 6;

/**
 * U19 / M14 / L2-T8 — the data-quality command centre over
 * `/api/v1/admin/data/quality*`, in four tabs: Overview (a card per
 * dimension, the entities below their target, the fields with the most open
 * issues, the latest scores with a trend), Rules (validity and consistency
 * rules), Issues (the steward's queue through its statuses) and Fixes (a
 * previewed, undoable bulk fix). The scores themselves are written by the
 * quality sweep (`EngineJob::DataQualityScoreSweep`), never here.
 */
@Component({
  selector: 'xrm-data-quality',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    FormsModule, LocalDatePipe, LocalNumberPipe, TranslatePipe, GovernanceNavComponent,
    QualityRulesComponent, QualityFixesComponent,
  ],
  styleUrls: ['../../../../styles/admin-page.css', '../governance.css', './data-quality.component.css'],
  templateUrl: './data-quality.component.html',
})
export class DataQualityComponent implements OnInit {
  private readonly svc = inject(DataQualityService);
  private readonly destroyRef = inject(DestroyRef);

  readonly dimensions = QUALITY_DIMENSIONS;
  readonly statuses = QUALITY_ISSUE_STATUSES;
  readonly tabs = QUALITY_TABS;
  readonly tab = signal<QualityTab>('overview');

  readonly targets = signal<QualityTarget[]>([]);
  /** The issue whose acceptance reason is being written. */
  readonly acceptingId = signal<string | null>(null);
  readonly acceptReason = signal('');
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

  /** A card per dimension the scores carry, `overall` last. */
  readonly dimensionCards = computed<DimensionCard[]>(() => {
    const byDimension = new Map<string, number[]>();
    for (const s of this.scores()) {
      const list = byDimension.get(s.dimension) ?? [];
      list.push(s.score);
      byDimension.set(s.dimension, list);
    }
    const order = (d: string) => {
      const i = (SCORE_DIMENSIONS as readonly string[]).indexOf(d);
      return i === -1 ? SCORE_DIMENSIONS.length - 1.5 : i;
    };
    return [...byDimension.entries()]
      .sort(([a], [b]) => order(a) - order(b))
      .map(([dimension, list]) => ({
        dimension,
        score: list.reduce((sum, v) => sum + v, 0) / list.length,
        entities: list.length,
      }));
  });

  /** Entities whose overall score is under their target's threshold. */
  readonly belowTarget = computed(() => {
    const overall = new Map(
      this.scores().filter(s => s.dimension === 'overall').map(s => [s.entity_logicalname, s.score]),
    );
    return this.targets()
      .filter(t => overall.has(t.entity) && (overall.get(t.entity) ?? 0) < t.threshold)
      .map(t => ({ entity: t.entity, score: overall.get(t.entity) ?? 0, threshold: t.threshold }));
  });

  /** The fields with the most open issues on the page read, five at most. */
  readonly worstFields = computed(() => {
    const counts = new Map<string, number>();
    for (const i of this.issues()) {
      if (i.status !== 'open') continue;
      const key = `${i.entity_logicalname}.${i.field_logicalname}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, 5)
      .map(([field, count]) => ({ field, count }));
  });

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
    this.loadTargets();
    this.loadIssues();
  }

  setTab(tab: QualityTab): void {
    this.tab.set(tab);
  }

  loadTargets(): void {
    this.svc.listTargets(this.entity()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: items => this.targets.set(items),
      // Targets only add the "below target" list; the rest stands without it.
      error: () => this.targets.set([]),
    });
  }

  /** Whether the API keeps a history for a score's dimension. */
  canTrend(s: QualityScore): boolean {
    return (QUALITY_DIMENSIONS as readonly string[]).includes(s.dimension);
  }

  /** L2-T4: moves an issue along its workflow; `accepted` asks for a reason
   * first. */
  moveIssue(issue: QualityIssue, status: QualityIssueStatus): void {
    if (status === 'accepted' && this.acceptingId() !== issue.id) {
      this.acceptingId.set(issue.id);
      this.acceptReason.set('');
      return;
    }
    const reason = status === 'accepted' ? this.acceptReason().trim() : undefined;
    if (status === 'accepted' && !reason) return;
    this.resolvingId.set(issue.id);
    this.notice.set(null);
    this.svc.setIssueStatus(issue.id, status, reason).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.resolvingId.set(null);
        this.acceptingId.set(null);
        this.notice.set('governance.quality.movedNotice');
        this.loadIssues();
      },
      error: (e: ApiError) => {
        this.resolvingId.set(null);
        this.issuesError.set(e.message);
      },
    });
  }

  refresh(): void {
    this.trendKey.set(null);
    this.issuesPage.set(1);
    this.loadScores();
    this.loadTargets();
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
