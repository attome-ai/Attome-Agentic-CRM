import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { DataQualityService } from '@attome/xrm/core/admin/data';
import type { QualityIssue, QualityScore } from '@attome/xrm/core/admin/data';
import { DataQualityComponent } from './data-quality.component';

describe('DataQualityComponent', () => {
  let fixture: ComponentFixture<DataQualityComponent>;
  let svc: {
    listScores: ReturnType<typeof vi.fn>;
    scoreHistory: ReturnType<typeof vi.fn>;
    listIssues: ReturnType<typeof vi.fn>;
    resolveIssue: ReturnType<typeof vi.fn>;
  };

  const score = (over: Partial<QualityScore> = {}): QualityScore => ({
    id: 's1', entity_logicalname: 'contact', period: '2026-09-22', dimension: 'completeness',
    pass_count: 90, fail_count: 10, sample_size: 100, score: 90, computed_at: '2026-09-22T02:00:00Z',
    ...over,
  });
  const issue = (over: Partial<QualityIssue> = {}): QualityIssue => ({
    id: 'i1', entity_logicalname: 'contact', period: '2026-09-22', dimension: 'completeness',
    record_id: 'r1', field_logicalname: 'email', related_record_id: null, detail: 'email is empty',
    status: 'open', detected_at: '2026-09-22T02:00:00Z', resolved_at: null,
    ...over,
  });

  async function render() {
    await TestBed.configureTestingModule({
      imports: [DataQualityComponent],
      providers: [
        provideRouter([]),
        { provide: DataQualityService, useValue: svc },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(DataQualityComponent);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      listScores: vi.fn().mockReturnValue(of([score(), score({ id: 's2', dimension: 'uniqueness', score: 60 })])),
      scoreHistory: vi.fn().mockReturnValue(of({
        items: [score({ id: 'h2', period: '2026-09-22', score: 90 }), score({ id: 'h1', period: '2026-09-21', score: 80 })],
        total: 2, page: 1, page_size: 30,
      })),
      listIssues: vi.fn().mockReturnValue(of({ items: [issue()], total: 1, page: 1, page_size: 50 })),
      resolveIssue: vi.fn().mockReturnValue(of(undefined)),
    };
  });

  it('lists the latest scores and asks for the open issue queue by default', async () => {
    await render();
    expect(el().querySelectorAll('section')[0].querySelectorAll('tbody tr').length).toBe(2);
    expect(svc.listIssues).toHaveBeenCalledWith({ entity: undefined, status: 'open', dimension: undefined }, 1, 50);
    expect(el().textContent).toContain('email is empty');
  });

  it('colours the score bar by band', async () => {
    await render();
    const fills = el().querySelectorAll('.dq-bar__fill--good, .dq-bar__fill--poor');
    expect(fills.length).toBe(2);
  });

  it('opens a trend for one entity+dimension and draws it oldest first', async () => {
    await render();
    fixture.componentInstance.toggleTrend(score());
    fixture.detectChanges();
    expect(svc.scoreHistory).toHaveBeenCalledWith('contact', 'completeness');
    const points = fixture.componentInstance.trendPoints();
    expect(points.map(p => p.period)).toEqual(['2026-09-21', '2026-09-22']);
    // A higher score sits higher on the chart (smaller y).
    expect(points[1].y).toBeLessThan(points[0].y);
    expect(el().querySelector('svg[role="img"]')).not.toBeNull();
  });

  it('resolves an issue and reloads the queue', async () => {
    await render();
    fixture.componentInstance.resolve(issue());
    expect(svc.resolveIssue).toHaveBeenCalledWith('i1');
    expect(svc.listIssues).toHaveBeenCalledTimes(2);
    expect(fixture.componentInstance.notice()).toBe('governance.quality.resolvedNotice');
  });

  it('treats a 409 on resolve as already resolved, not an error', async () => {
    svc.resolveIssue.mockReturnValue(throwError(() => ({ status: 409, kind: 'conflict', message: 'already' })));
    await render();
    fixture.componentInstance.resolve(issue());
    expect(fixture.componentInstance.notice()).toBe('governance.quality.alreadyResolved');
    expect(fixture.componentInstance.issuesError()).toBeNull();
  });

  it('re-queries issues from page 1 when a filter changes', async () => {
    await render();
    fixture.componentInstance.issuesPage.set(3);
    fixture.componentInstance.setIssueDimension('uniqueness');
    expect(svc.listIssues).toHaveBeenLastCalledWith({ entity: undefined, status: 'open', dimension: 'uniqueness' }, 1, 50);
  });
});
