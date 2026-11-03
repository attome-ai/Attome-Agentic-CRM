import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import { GraphCanvasComponent, edgeKey, type GraphDoc, type GraphDocNode } from '@attome/xrm/canvas';

import {
  type FlowCoverage, type SimulateNodeTrace, type SimulateResponse, WorkflowAdminService,
} from '../services/workflow-admin.service';
import { coverageMarks, simulatedPath, simulationMarks } from './simulation-view.component';
import { WorkflowDesignerComponent } from './workflow-designer.component';

// M4-T4: a simulated run lights its path on the canvas; coverage shades the
// nodes no test case reached.

function node(id: string, type: string): GraphDocNode {
  return { id, type, config: {}, ports: { x: 0, y: 0 } };
}
const edge = (from_node: string, from_port: string, to_node: string, to_port: string) =>
  ({ from_node, from_port, to_node, to_port });
function trace(node_id: string, status: string, taken_port: string | null = null): SimulateNodeTrace {
  return { node_id, node_type: 'x', status, taken_port, output: null, would_have: null, error: null };
}

const FLOW: GraphDoc = {
  nodes: [node('t', 'trigger'), node('c', 'condition'), node('yes', 'wait'), node('no', 'wait'), node('oops', 'wait')],
  edges: [
    edge('t', 'out', 'c', 'value'), edge('c', 'true', 'yes', 'in'), edge('c', 'false', 'no', 'in'),
    edge('yes', 'on_error', 'oops', 'in'),
  ],
};
const RUN: SimulateResponse = {
  status: 'completed',
  trace: [trace('t', 'succeeded'), trace('c', 'succeeded', 'true'), trace('yes', 'succeeded'), trace('no', 'skipped'), trace('oops', 'skipped')],
};
const COVERAGE: FlowCoverage = {
  tests: [{ id: 'a', name: 'happy path', blocking: true, passed: true, failures: [] }],
  covered: ['t', 'c', 'yes'], uncovered: ['no', 'oops'],
};

function setup(simulate: () => unknown = () => of(RUN), coverage: () => unknown = () => of(COVERAGE)) {
  const svc = {
    getVersion: vi.fn(() => of({
      id: 'v1', definition_id: 'd1', version_number: 1, graph: FLOW, status: 'draft', published_at: null,
      row_version: 1, created_at: '2026-11-03T00:00:00Z',
    })),
    listDefinitions: vi.fn(() => of([])),
    simulateVersion: vi.fn(simulate),
    versionCoverage: vi.fn(coverage),
  };
  TestBed.configureTestingModule({
    imports: [WorkflowDesignerComponent],
    providers: [
      provideRouter([]),
      { provide: WorkflowAdminService, useValue: svc },
      { provide: AdminService, useValue: { listEntities: vi.fn(() => of([])) } },
      { provide: LangService, useValue: { translate: (key: string) => key } },
    ],
  });
  const fixture = TestBed.createComponent(WorkflowDesignerComponent);
  fixture.componentRef.setInput('definitionId', 'd1');
  fixture.componentRef.setInput('versionId', 'v1');
  fixture.detectChanges();
  const el = fixture.nativeElement as HTMLElement;
  const click = (id: string) => {
    (el.querySelector(`[data-testid="${id}"]`) as HTMLButtonElement).click();
    fixture.detectChanges();
  };
  const marks = (id: string) => el.querySelector(`[data-node="${id}"]`)?.getAttribute('data-marks') ?? '';
  const canvas = () => fixture.debugElement.query(d => d.componentInstance instanceof GraphCanvasComponent)
    .componentInstance as GraphCanvasComponent;
  return { fixture, el, c: fixture.componentInstance, svc, click, marks, canvas };
}

describe('simulatedPath', () => {
  it('follows the port a branch took and the nodes the run reached', () => {
    expect(simulatedPath(RUN, FLOW)).toEqual([edgeKey(FLOW.edges[0]), edgeKey(FLOW.edges[1])]);
  });

  it('leaves by the error port only when a node failed', () => {
    const reached: SimulateResponse = {
      status: 'failed',
      trace: [trace('t', 'succeeded'), trace('c', 'succeeded', 'true'), trace('yes', 'failed'), trace('oops', 'succeeded')],
    };
    expect(simulatedPath(reached, FLOW)).toContain(edgeKey(FLOW.edges[3]));
    const fine: SimulateResponse = { status: 'completed', trace: [trace('yes', 'succeeded'), trace('oops', 'succeeded')] };
    expect(simulatedPath(fine, FLOW)).toEqual([]);
  });

  it('is empty without a run', () => {
    expect(simulatedPath(null, FLOW)).toEqual([]);
  });
});

describe('marks', () => {
  it('names what each node did', () => {
    const marks = simulationMarks(RUN, s => s);
    expect(marks['yes']).toEqual([{ tone: 'ran', note: 'succeeded' }]);
    expect(marks['no']).toEqual([{ tone: 'skipped', note: 'skipped' }]);
    const failed = simulationMarks({ status: 'failed', trace: [trace('a', 'failed'), trace('b', 'waiting')] }, s => s);
    expect(failed['a'][0].tone).toBe('failed');
    expect(failed['b'][0].tone).toBe('ran');
  });

  it('shades only what no test reached', () => {
    expect(Object.keys(coverageMarks(COVERAGE, 'gap'))).toEqual(['no', 'oops']);
    expect(coverageMarks(null, 'gap')).toEqual({});
  });
});

describe('the designer', () => {
  beforeEach(() => TestBed.resetTestingModule());

  it('lights the simulated path and marks each node', () => {
    const { el, svc, click, marks } = setup();
    click('wd-simulate');
    expect(svc.simulateVersion).toHaveBeenCalledWith('d1', 'v1', { trigger_payload: {} });
    expect(marks('yes')).toContain('ran');
    expect(marks('no')).toContain('skipped');
    expect(el.querySelectorAll('.gc-wire--lit').length).toBe(2);
    expect(el.querySelector('[data-testid="sv-status"]')?.textContent).toContain('simulation.result.completed');
    expect(el.querySelectorAll('[data-testid="sv-row"]').length).toBe(5);
    // Each mark has a symbol, not only a colour, and its note is in the card's name.
    expect(el.querySelector('[data-node="yes"] [data-testid="graph-mark"]')?.textContent).toBe('✓');
    expect(el.querySelector('[data-node="yes"]')?.getAttribute('aria-label')).toContain('simulation.status.succeeded');
  });

  it('shades uncovered nodes and reports the test cases', () => {
    const { el, click, marks } = setup();
    click('wd-coverage');
    expect(marks('no')).toContain('uncovered');
    expect(marks('oops')).toContain('uncovered');
    expect(marks('yes')).not.toContain('uncovered');
    expect(el.querySelector('[data-testid="sv-coverage"]')).toBeTruthy();
    expect(el.querySelector('.sv-tests')?.textContent).toContain('happy path');
  });

  it('says when a flow has no test cases', () => {
    const { el, click } = setup(undefined, () => of({ tests: [], covered: [], uncovered: ['t'] }));
    click('wd-coverage');
    expect(el.querySelector('[data-testid="sv-no-tests"]')).toBeTruthy();
  });

  it('a row selects its node', () => {
    const { fixture, el, c, click } = setup();
    click('wd-simulate');
    (el.querySelector('[data-status="skipped"] .sv-node') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(c.selected()).toBe('no');
  });

  it('clears when asked, and when the graph changes', () => {
    const { fixture, el, click, marks, canvas } = setup();
    click('wd-simulate');
    click('sv-close');
    expect(el.querySelector('[data-testid="simulation-view"]')).toBeNull();
    expect(marks('yes')).not.toContain('ran');
    click('wd-simulate');
    canvas().selectNode('yes');
    canvas().onKey(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="simulation-view"]')).toBeNull();
    expect(el.querySelectorAll('.gc-wire--lit').length).toBe(0);
  });

  it('does not simulate a graph with unsaved changes', () => {
    const { fixture, el, svc, canvas } = setup();
    canvas().selectNode('yes');
    canvas().onKey(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
    fixture.detectChanges();
    expect((el.querySelector('[data-testid="wd-simulate"]') as HTMLButtonElement).disabled).toBe(true);
    expect(svc.simulateVersion).not.toHaveBeenCalled();
  });

  it('shows the server\'s message when the run is refused', () => {
    const { el, click } = setup(() => throwError(() => ({ message: 'no permission' })));
    click('wd-simulate');
    expect(el.querySelector('[data-testid="wd-save-error"]')?.textContent).toContain('no permission');
  });
});
