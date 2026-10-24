import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { DataQualityService } from '@attome/xrm/core/admin/data';
import type { QualityIssue, QualityRule, QualityScore } from '@attome/xrm/core/admin/data';
import { DataQualityComponent } from './data-quality.component';
import { QualityFixesComponent } from './quality-fixes.component';
import { QualityRulesComponent } from './quality-rules.component';

type Mocked = Record<string, ReturnType<typeof vi.fn>>;

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
const rule = (over: Partial<QualityRule> = {}): QualityRule => ({
  id: 'q1', entity: 'deal', attribute: 'amount', dimension: 'validity', expression: 'amount >= 0',
  severity: 'error', weight: 2, enabled: true, row_version: 3,
  ...over,
});

function service(): Mocked {
  return {
    listScores: vi.fn().mockReturnValue(of([
      score(),
      score({ id: 's2', dimension: 'uniqueness', score: 60 }),
      score({ id: 's3', dimension: 'overall', score: 65 }),
    ])),
    scoreHistory: vi.fn().mockReturnValue(of({
      items: [score({ id: 'h2', period: '2026-09-22', score: 90 }), score({ id: 'h1', period: '2026-09-21', score: 80 })],
      total: 2, page: 1, page_size: 30,
    })),
    listTargets: vi.fn().mockReturnValue(of([
      { entity: 'contact', dimension_weights: {}, threshold: 80, record_scoring: false },
    ])),
    listIssues: vi.fn().mockReturnValue(of({
      items: [issue(), issue({ id: 'i2', record_id: 'r2' }), issue({ id: 'i3', field_logicalname: 'phone', record_id: 'r3' })],
      total: 3, page: 1, page_size: 50,
    })),
    resolveIssue: vi.fn().mockReturnValue(of(undefined)),
    setIssueStatus: vi.fn().mockReturnValue(of(undefined)),
    listRules: vi.fn().mockReturnValue(of([rule()])),
    createRule: vi.fn().mockReturnValue(of(rule())),
    updateRule: vi.fn().mockReturnValue(of(rule())),
    deleteRule: vi.fn().mockReturnValue(of(undefined)),
    previewFix: vi.fn().mockReturnValue(of({
      matched: 2, to_change: 1, unchanged: 1,
      samples: [{ id: 'r1', before: { email: ' a@b.sa ' }, after: { email: 'a@b.sa' } }],
    })),
    applyFix: vi.fn().mockReturnValue(of({
      total: 2, matched: 2, unchanged: 1, record_ids: ['r1'], id: 'b1', approval_request_id: null,
      undo: [{ id: 'r1', row_version: 5, values: { email: ' a@b.sa ' } }],
    })),
    undoFix: vi.fn().mockReturnValue(of({})),
  };
}

function lang(rtl = false) {
  return { translate: (key: string) => key, intlLocale: () => 'en-US', isRtl: () => rtl };
}

describe('DataQualityComponent', () => {
  let fixture: ComponentFixture<DataQualityComponent>;
  let svc: Mocked;

  async function render() {
    await TestBed.configureTestingModule({
      imports: [DataQualityComponent],
      providers: [
        provideRouter([]),
        { provide: DataQualityService, useValue: svc },
        { provide: LangService, useValue: lang() },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(DataQualityComponent);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;
  const openTab = (tab: string) => {
    el().querySelector<HTMLButtonElement>(`[data-tab="${tab}"]`)!.click();
    fixture.detectChanges();
  };

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = service();
  });

  it('lists the latest scores and asks for the open issue queue by default', async () => {
    await render();
    expect(el().querySelectorAll('section')[0].querySelectorAll('tbody tr').length).toBe(3);
    expect(svc['listIssues']).toHaveBeenCalledWith({ entity: undefined, status: 'open', dimension: undefined }, 1, 50);
    openTab('issues');
    expect(el().textContent).toContain('email is empty');
  });

  it('shows a card per dimension, overall last, and the entities below their target', async () => {
    await render();
    const cards = fixture.componentInstance.dimensionCards();
    expect(cards.map(c => c.dimension)).toEqual(['completeness', 'uniqueness', 'overall']);
    expect(el().querySelectorAll('[data-dimension-cards] .dq-card').length).toBe(3);
    expect(fixture.componentInstance.belowTarget()).toEqual([{ entity: 'contact', score: 65, threshold: 80 }]);
    expect(el().querySelector('[data-below-target]')?.textContent).toContain('contact');
    // email has two open issues, phone one.
    expect(fixture.componentInstance.worstFields()).toEqual([
      { field: 'contact.email', count: 2 }, { field: 'contact.phone', count: 1 },
    ]);
  });

  it('colours the score bar by band', async () => {
    await render();
    const fills = el().querySelectorAll('.dq-bar__fill--good, .dq-bar__fill--poor');
    expect(fills.length).toBe(3);
  });

  it('opens a trend for one entity+dimension and draws it oldest first', async () => {
    await render();
    fixture.componentInstance.toggleTrend(score());
    fixture.detectChanges();
    expect(svc['scoreHistory']).toHaveBeenCalledWith('contact', 'completeness');
    const points = fixture.componentInstance.trendPoints();
    expect(points.map(p => p.period)).toEqual(['2026-09-21', '2026-09-22']);
    // A higher score sits higher on the chart (smaller y).
    expect(points[1].y).toBeLessThan(points[0].y);
    expect(el().querySelector('svg[role="img"]')).not.toBeNull();
    // The overall score has no history to draw.
    expect(fixture.componentInstance.canTrend(score({ dimension: 'overall' }))).toBe(false);
  });

  it('resolves an issue and reloads the queue', async () => {
    await render();
    fixture.componentInstance.resolve(issue());
    expect(svc['resolveIssue']).toHaveBeenCalledWith('i1');
    expect(svc['listIssues']).toHaveBeenCalledTimes(2);
    expect(fixture.componentInstance.notice()).toBe('governance.quality.resolvedNotice');
  });

  it('treats a 409 on resolve as already resolved, not an error', async () => {
    svc['resolveIssue'].mockReturnValue(throwError(() => ({ status: 409, kind: 'conflict', message: 'already' })));
    await render();
    fixture.componentInstance.resolve(issue());
    expect(fixture.componentInstance.notice()).toBe('governance.quality.alreadyResolved');
    expect(fixture.componentInstance.issuesError()).toBeNull();
  });

  it('moves an issue through its workflow and asks why before accepting it', async () => {
    await render();
    openTab('issues');
    el().querySelector<HTMLButtonElement>('[data-issue-start]')!.click();
    expect(svc['setIssueStatus']).toHaveBeenCalledWith('i1', 'in_progress', undefined);

    const c = fixture.componentInstance;
    c.moveIssue(issue(), 'accepted');
    expect(c.acceptingId()).toBe('i1');
    expect(svc['setIssueStatus']).toHaveBeenCalledTimes(1);
    c.acceptReason.set('a shared mailbox, on purpose');
    c.moveIssue(issue(), 'accepted');
    expect(svc['setIssueStatus']).toHaveBeenLastCalledWith('i1', 'accepted', 'a shared mailbox, on purpose');
  });

  it('re-queries issues from page 1 when a filter changes', async () => {
    await render();
    fixture.componentInstance.issuesPage.set(3);
    fixture.componentInstance.setIssueDimension('uniqueness');
    expect(svc['listIssues']).toHaveBeenLastCalledWith({ entity: undefined, status: 'open', dimension: 'uniqueness' }, 1, 50);
  });

  it('opens the rules and fixes tabs', async () => {
    await render();
    openTab('rules');
    expect(el().querySelector('xrm-quality-rules')).not.toBeNull();
    expect(el().textContent).toContain('amount >= 0');
    openTab('fixes');
    expect(el().querySelector('xrm-quality-fixes')).not.toBeNull();
  });
});

describe('QualityRulesComponent', () => {
  let svc: Mocked;

  async function render() {
    await TestBed.configureTestingModule({
      imports: [QualityRulesComponent],
      providers: [
        { provide: DataQualityService, useValue: svc },
        { provide: LangService, useValue: lang() },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(QualityRulesComponent);
    fixture.componentRef.setInput('entity', 'deal');
    fixture.detectChanges();
    return fixture;
  }

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = service();
  });

  it('lists the entity rules, creates one and edits one against its version', async () => {
    const fixture = await render();
    expect(svc['listRules']).toHaveBeenCalledWith('deal');
    const c = fixture.componentInstance;
    c.startNew();
    c.draft()!.expression = 'close_date >= created_at';
    c.draft()!.dimension = 'consistency';
    c.save();
    expect(svc['createRule']).toHaveBeenCalledWith(expect.objectContaining({
      entity: 'deal', dimension: 'consistency', expression: 'close_date >= created_at',
    }));
    c.edit(rule());
    c.draft()!.weight = 4;
    c.save();
    expect(svc['updateRule']).toHaveBeenCalledWith('q1', expect.objectContaining({ row_version: 3, weight: 4 }));
  });

  it('says a stale edit is a conflict', async () => {
    svc['updateRule'].mockReturnValue(throwError(() => ({ status: 409, message: 'version_conflict' })));
    const fixture = await render();
    const c = fixture.componentInstance;
    c.edit(rule());
    c.save();
    expect(c.formError()).toBe('governance.quality.rules.conflict');
    expect(c.draft()).not.toBeNull();
  });
});

describe('QualityFixesComponent', () => {
  let svc: Mocked;

  async function render(rtl = false) {
    await TestBed.configureTestingModule({
      imports: [QualityFixesComponent],
      providers: [
        { provide: DataQualityService, useValue: svc },
        { provide: LangService, useValue: lang(rtl) },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(QualityFixesComponent);
    fixture.componentRef.setInput('entity', 'contact');
    fixture.detectChanges();
    return fixture;
  }

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = service();
  });

  it('previews a fix over the records with open issues on the field, applies it and undoes it', async () => {
    const fixture = await render();
    const c = fixture.componentInstance;
    c.attribute.set('email');
    c.preview();
    expect(svc['listIssues']).toHaveBeenCalledWith({ entity: 'contact', status: 'open' }, 1, 200);
    expect(svc['previewFix']).toHaveBeenCalledWith({
      entity: 'contact', attribute: 'email', fix: 'trim_spaces', ids: ['r1', 'r2'],
    });
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-fix-result]')?.textContent).toContain('a@b.sa');

    el.querySelector<HTMLButtonElement>('[data-fix-apply]')!.click();
    expect(svc['applyFix']).toHaveBeenCalledTimes(1);
    fixture.detectChanges();
    el.querySelector<HTMLButtonElement>('[data-fix-undo]')!.click();
    expect(svc['undoFix']).toHaveBeenCalledWith('contact', [{ id: 'r1', row_version: 5, values: { email: ' a@b.sa ' } }]);
    expect(c.undone()).toBe(true);
  });

  it('names the country for a phone fix and says when there is nothing to fix', async () => {
    const fixture = await render();
    const c = fixture.componentInstance;
    c.attribute.set('phone');
    c.fix.set('phone_e164');
    c.country.set('ae');
    c.preview();
    expect(svc['previewFix']).toHaveBeenCalledWith(expect.objectContaining({
      fix: { fix: 'phone_e164', country: 'AE' }, ids: ['r3'],
    }));
    c.attribute.set('website');
    c.preview();
    expect(c.error()).toBe('governance.quality.fixes.nothing');
  });

  it('reads before and after in the page direction (RTL)', async () => {
    const fixture = await render(true);
    const c = fixture.componentInstance;
    expect(c.arrow()).toBe('←');
    c.attribute.set('email');
    c.preview();
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('.dq-arrow')?.textContent?.trim()).toBe('←');
  });
});
