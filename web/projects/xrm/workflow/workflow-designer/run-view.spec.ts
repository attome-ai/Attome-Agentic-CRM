import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { Subject, of, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { GraphCanvasComponent, edgeKey, type GraphDoc, type GraphDocNode } from '@attome/xrm/canvas';

import { type InstanceDetail, type NodeRunSummary, WorkflowAdminService } from '../services/workflow-admin.service';
import { replayOrder, runDuration, runMarks, runPath, runsAt, WorkflowRunViewComponent } from './run-view.component';

// M2-T3: a run on the graph: nodes by state, inspect a node, watch while it
// goes on, replay forward and back from the run record.

function node(id: string, type: string): GraphDocNode {
  return { id, type, config: {}, ports: { x: 0, y: 0 } };
}
const edge = (from_node: string, from_port: string, to_node: string, to_port: string) =>
  ({ from_node, from_port, to_node, to_port });

function run(node_id: string, status: string, minute: number | null, over: Partial<NodeRunSummary> = {}): NodeRunSummary {
  const at = minute === null ? null : `2026-11-03T10:0${minute}:00Z`;
  return {
    node_id, status, attempt_count: 1, last_error: null, started_at: at, completed_at: at, round: 0,
    input: { in: node_id }, output: { out: node_id }, payload_ref: null, ...over,
  } as NodeRunSummary;
}

const FLOW: GraphDoc = {
  nodes: [node('t', 'trigger'), node('hook', 'webhook'), node('after', 'wait'), node('oops', 'wait'), node('later', 'wait')],
  edges: [
    edge('t', 'out', 'hook', 'body'), edge('hook', 'response', 'after', 'in'), edge('hook', 'on_error', 'oops', 'in'),
    edge('after', 'out', 'later', 'in'),
  ],
};
const RUNS = [run('after', 'running', 2), run('t', 'completed', 0), run('hook', 'completed', 1)];

function instance(status: string, node_runs: NodeRunSummary[] = RUNS): InstanceDetail {
  return {
    id: 'i1', definition_id: 'd1', definition_version_id: 'v1', status, started_at: '2026-11-03T10:00:00Z',
    completed_at: null, started_by: null, correlation_entity_id: null, context: {}, node_data: {}, row_version: 1,
    node_runs,
  };
}

function setup(getInstance: () => unknown = () => of(instance('completed')), getVersion: () => unknown = () => of({ graph: FLOW })) {
  const svc = { getInstance: vi.fn(getInstance), getVersion: vi.fn(getVersion) };
  TestBed.configureTestingModule({
    imports: [WorkflowRunViewComponent],
    providers: [
      provideRouter([]),
      { provide: WorkflowAdminService, useValue: svc },
      { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
    ],
  });
  const fixture = TestBed.createComponent(WorkflowRunViewComponent);
  fixture.componentRef.setInput('id', 'i1');
  fixture.detectChanges();
  const el = fixture.nativeElement as HTMLElement;
  const marks = (id: string) => el.querySelector(`[data-node="${id}"]`)?.getAttribute('data-marks') ?? '';
  const click = (id: string) => {
    (el.querySelector(`[data-testid="${id}"]`) as HTMLButtonElement).click();
    fixture.detectChanges();
  };
  const canvas = () => fixture.debugElement.query(d => d.componentInstance instanceof GraphCanvasComponent)
    .componentInstance as GraphCanvasComponent;
  return { fixture, el, c: fixture.componentInstance, svc, marks, click, canvas };
}

describe('the run record', () => {
  it('orders by start, what has not started last', () => {
    const ordered = replayOrder([run('c', 'pending', null), ...RUNS]);
    expect(ordered.map(r => r.node_id)).toEqual(['t', 'hook', 'after', 'c']);
    expect(replayOrder([run('a', 'completed', 0, { round: 1 }), run('a', 'completed', 0, { round: 0 })]).map(r => r.round)).toEqual([0, 1]);
  });

  it('gives the runs at a step, and all of them for now', () => {
    expect(runsAt(RUNS, 0).map(r => r.node_id)).toEqual(['t']);
    expect(runsAt(RUNS, 1).map(r => r.node_id)).toEqual(['t', 'hook']);
    expect(runsAt(RUNS, null).length).toBe(3);
  });

  it('marks a node by its latest run', () => {
    const marks = runMarks([run('a', 'completed', 0), run('a', 'failed', 1), run('b', 'skipped', 1), run('c', 'waiting', 1)], s => s);
    expect(marks['a']).toEqual([{ tone: 'failed', note: 'failed' }]);
    expect(marks['b'][0].tone).toBe('skipped');
    expect(marks['c'][0].tone).toBe('active');
  });

  it('follows the edges between reached nodes, the error port only after a failure', () => {
    expect(runPath(runsAt(RUNS, null), FLOW)).toEqual([edgeKey(FLOW.edges[0]), edgeKey(FLOW.edges[1])]);
    const failed = [run('t', 'completed', 0), run('hook', 'failed', 1), run('oops', 'completed', 2)];
    expect(runPath(failed, FLOW)).toEqual([edgeKey(FLOW.edges[0]), edgeKey(FLOW.edges[2])]);
    const skipped = [run('t', 'completed', 0), run('hook', 'completed', 1), run('after', 'skipped', 2)];
    expect(runPath(skipped, FLOW)).toEqual([edgeKey(FLOW.edges[0])]);
  });

  it('times a finished run', () => {
    expect(runDuration({ started_at: '2026-11-03T10:00:00Z', completed_at: '2026-11-03T10:00:02Z' })).toBe(2000);
    expect(runDuration({ started_at: '2026-11-03T10:00:00Z', completed_at: null })).toBeNull();
  });
});

describe('WorkflowRunViewComponent', () => {
  beforeEach(() => TestBed.resetTestingModule());
  afterEach(() => vi.useRealTimers());

  it('opens the run on the graph it ran, nodes by state, read-only', () => {
    const { el, svc, marks } = setup();
    expect(svc.getVersion).toHaveBeenCalledWith('d1', 'v1');
    expect(marks('t')).toBe('ran');
    expect(marks('after')).toBe('active');
    expect(marks('later')).toBe('');
    expect(el.querySelectorAll('.gc-wire--lit').length).toBe(2);
    expect((el.querySelector('[data-node="t"] [data-testid="graph-port-out"]') as HTMLButtonElement).disabled).toBe(true);
    expect(el.querySelector('[data-testid="graph-save"]')).toBeNull();
  });

  it('shows a node\'s input, output, time and error', () => {
    const failed = run('hook', 'failed', 1, {
      last_error: 'bad gateway', attempt_count: 3, completed_at: '2026-11-03T10:01:02Z',
      input: { headers: { Authorization: '••••••' }, q: 1 },
    });
    const { fixture, el, canvas } = setup(() => of(instance('failed', [run('t', 'completed', 0), failed])));
    canvas().selectNode('hook');
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="rv-input"]')?.textContent).toContain('••••••');
    expect(el.querySelector('[data-testid="rv-output"]')?.textContent).toContain('hook');
    expect(el.querySelector('[data-testid="rv-node-error"]')?.textContent).toContain('bad gateway');
    expect(el.querySelector('[data-testid="rv-took"]')).toBeTruthy();
  });

  it('shows each round of a looped node, and says when a pair is kept in storage', () => {
    const rounds = [run('hook', 'completed', 1, { round: 0 }), run('hook', 'completed', 2, { round: 1, payload_ref: 'k', input: null, output: null })];
    const { fixture, el, canvas } = setup(() => of(instance('completed', rounds)));
    canvas().selectNode('hook');
    fixture.detectChanges();
    expect(el.querySelectorAll('[data-testid="rv-run"]').length).toBe(2);
    expect(el.querySelector('[data-testid="rv-large"]')).toBeTruthy();
  });

  it('shows a run that took no time, and names statuses', () => {
    const quick = run('hook', 'completed', 1);
    const { fixture, el, canvas } = setup(() => of(instance('completed', [quick])));
    canvas().selectNode('hook');
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="rv-took"]')).toBeTruthy();
    expect(el.querySelector('[data-testid="rv-run-status"]')?.textContent).toContain('completed');
  });

  it('an answer after the page closed starts no further read', () => {
    vi.useFakeTimers();
    const answer = new Subject<InstanceDetail>();
    const { fixture, svc } = setup(() => answer);
    fixture.destroy();
    answer.next(instance('running'));
    vi.advanceTimersByTime(20000);
    expect(svc.getInstance).toHaveBeenCalledTimes(1);
  });

  it('says when a node has not run', () => {
    const { fixture, el, canvas } = setup();
    canvas().selectNode('later');
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="rv-not-run"]')).toBeTruthy();
  });

  it('replays back and forward, showing the graph at each step', () => {
    const { el, c, marks, click } = setup();
    expect(c.step()).toBeNull();
    expect((el.querySelector('[data-testid="rv-forward"]') as HTMLButtonElement).disabled).toBe(true);
    click('rv-back');
    expect(c.step()).toBe(1);
    expect(c.selected()).toBe('hook');
    expect(marks('after')).toBe('');
    expect(marks('hook')).toBe('ran');
    expect(el.querySelectorAll('.gc-wire--lit').length).toBe(1);
    click('rv-back');
    expect(c.step()).toBe(0);
    expect(marks('hook')).toBe('');
    expect((el.querySelector('[data-testid="rv-back"]') as HTMLButtonElement).disabled).toBe(true);
    click('rv-forward');
    expect(c.step()).toBe(1);
    click('rv-forward');
    expect(c.step()).toBeNull();
    expect(marks('after')).toBe('active');
  });

  it('jumps back to now', () => {
    const { c, click } = setup();
    click('rv-back');
    click('rv-live');
    expect(c.step()).toBeNull();
  });

  it('watches a run going on and stops when it ends', () => {
    vi.useFakeTimers();
    const answers = [instance('running'), instance('running'), instance('completed')];
    const { fixture, el, svc, marks } = setup(() => of(answers.shift() ?? instance('completed')));
    expect(el.querySelector('[data-testid="rv-watching"]')).toBeTruthy();
    expect(svc.getInstance).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(5000);
    expect(svc.getInstance).toHaveBeenCalledTimes(2);
    vi.advanceTimersByTime(5000);
    fixture.detectChanges();
    expect(svc.getInstance).toHaveBeenCalledTimes(3);
    expect(el.querySelector('[data-testid="rv-watching"]')).toBeNull();
    vi.advanceTimersByTime(20000);
    expect(svc.getInstance).toHaveBeenCalledTimes(3);
    expect(svc.getVersion).toHaveBeenCalledTimes(1);
    expect(marks('t')).toBe('ran');
  });

  it('keeps the last answer when a re-read fails, and stops watching when destroyed', () => {
    vi.useFakeTimers();
    let calls = 0;
    const { fixture, el, svc } = setup(() => {
      calls += 1;
      return calls === 2 ? throwError(() => ({ message: 'gone' })) : of(instance('running'));
    });
    vi.advanceTimersByTime(5000);
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="rv-error"]')).toBeNull();
    expect(el.querySelector('[data-node="t"]')).toBeTruthy();
    vi.advanceTimersByTime(5000);
    expect(svc.getInstance).toHaveBeenCalledTimes(3);
    fixture.destroy();
    vi.advanceTimersByTime(20000);
    expect(svc.getInstance).toHaveBeenCalledTimes(3);
  });

  it('shows the server\'s message when the run cannot be read', () => {
    const { el } = setup(() => throwError(() => ({ message: 'no access' })));
    expect(el.querySelector('[data-testid="rv-error"]')?.textContent).toContain('no access');
  });
});
