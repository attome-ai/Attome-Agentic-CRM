import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import { type GraphDoc, type GraphDocNode } from '@attome/xrm/canvas';

import { NODE_TYPES, WorkflowAdminService } from '../services/workflow-admin.service';
import { earlierNodes } from './mapping-panel.component';
import { mapConfigOk, publishProblems } from './publish-check';
import { WorkflowDesignerComponent } from './workflow-designer.component';

// M2-T2: the mapping panel lists every earlier node's typed outputs and maps
// them to inputs; the publish checks run on every change and mark the nodes.

function node(id: string, type: string, config: Record<string, unknown> = {}): GraphDocNode {
  return { id, type, config, ports: { x: 0, y: 0 } };
}

const edge = (from_node: string, from_port: string, to_node: string, to_port: string) =>
  ({ from_node, from_port, to_node, to_port });

const FLOW: GraphDoc = {
  nodes: [node('t', 'trigger'), node('make', 'create_record'), node('change', 'update_record'), node('after', 'wait')],
  edges: [edge('t', 'out', 'make', 'data'), edge('change', 'record', 'after', 'in')],
};

const keysOf = (doc: GraphDoc, at: string | null) =>
  publishProblems(doc, NODE_TYPES).filter(p => p.node === at).map(p => p.key);

function setup(graph: GraphDoc = FLOW, status = 'draft') {
  const svc = {
    getVersion: vi.fn(() => of({
      id: 'v1', definition_id: 'd1', version_number: 1, graph, status, published_at: null, row_version: 1,
      created_at: '2026-11-03T00:00:00Z',
    })),
    listDefinitions: vi.fn(() => of([])),
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
  const c = fixture.componentInstance;
  const select = (id: string) => { c.pick(id); fixture.detectChanges(); };
  const panel = () => el.querySelector('[data-testid="mapping-panel"]') as HTMLElement;
  const output = (nodeId: string, port: string) =>
    panel().querySelector(`[data-testid="mp-node"][data-node="${nodeId}"] [data-testid="mp-output"][data-port="${port}"]`) as HTMLButtonElement;
  const input = (port: string) => panel().querySelector(`[data-testid="mp-input"][data-port="${port}"]`) as HTMLButtonElement;
  return { fixture, el, c, select, panel, output, input };
}

describe('earlierNodes', () => {
  it('lists upstream nodes first, then unconnected ones, never the node or what follows it', () => {
    const list = earlierNodes(FLOW, NODE_TYPES, 'make');
    expect(list.map(e => [e.node.id, e.upstream])).toEqual([['t', true], ['change', false], ['after', false]]);
    const after = earlierNodes(FLOW, NODE_TYPES, 'change');
    expect(after.map(e => e.node.id)).toEqual(['t', 'make']);
  });

  it('carries each output\'s type, the error port included', () => {
    const make = earlierNodes(FLOW, NODE_TYPES, 'change').find(e => e.node.id === 'make');
    expect(make?.outputs.map(p => [p.name, p.portType])).toEqual([['record', 'record_id'], ['on_error', 'json']]);
  });
});

describe('the mapping panel in the designer', () => {
  beforeEach(() => TestBed.resetTestingModule());

  it('shows the selected step\'s inputs and what feeds them', () => {
    const { select, panel } = setup();
    select('make');
    const row = panel().querySelector('[data-testid="mp-input-row"][data-port="data"]') as HTMLElement;
    expect(row.querySelector('[data-testid="mp-source"]')?.textContent).toContain('t.out');
    select('change');
    expect(panel().querySelectorAll('[data-testid="mp-unmapped"]').length).toBe(2);
  });

  it('maps an output to an input by choosing one then the other', () => {
    const { fixture, c, select, output, input, panel } = setup();
    select('change');
    output('make', 'record').click();
    fixture.detectChanges();
    expect(output('make', 'record').getAttribute('aria-pressed')).toBe('true');
    expect(input('record_id').classList).toContain('mp-ok');
    expect(input('data').classList).toContain('mp-no');
    input('record_id').click();
    fixture.detectChanges();
    expect(c.current().edges).toContainEqual(edge('make', 'record', 'change', 'record_id'));
    expect(panel().querySelector('[data-testid="mp-source"]')?.textContent).toContain('make.record');
  });

  it('maps by dragging an output onto an input', () => {
    const { fixture, c, select, output, input } = setup();
    select('change');
    output('make', 'record').dispatchEvent(new Event('dragstart', { bubbles: true }));
    fixture.detectChanges();
    input('record_id').dispatchEvent(new Event('drop', { bubbles: true, cancelable: true }));
    fixture.detectChanges();
    expect(c.current().edges).toContainEqual(edge('make', 'record', 'change', 'record_id'));
  });

  it('refuses a drop whose types do not meet, and says why', () => {
    const { fixture, c, select, output, input, panel } = setup();
    select('change');
    output('make', 'record').click();
    fixture.detectChanges();
    input('data').click();
    fixture.detectChanges();
    expect(c.current().edges.length).toBe(2);
    expect(panel().querySelector('[data-testid="mp-status"]')?.textContent).toContain('graphCanvas.refuse.type');
  });

  it('removes a mapping', () => {
    const { fixture, c, select, panel } = setup();
    select('make');
    (panel().querySelector('[data-testid="mp-remove"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(c.current().edges).toEqual([edge('change', 'record', 'after', 'in')]);
  });

  it('is view only on a published version', () => {
    const { select, panel, output } = setup(FLOW, 'published');
    select('make');
    expect(output('change', 'record').disabled).toBe(true);
    expect(panel().querySelector('[data-testid="mp-remove"]')).toBeNull();
  });
});

describe('live validation', () => {
  beforeEach(() => TestBed.resetTestingModule());

  it('marks problems on their nodes as the builder edits, and clears them when fixed', () => {
    const { fixture, el, c, select, output, input } = setup();
    // `change` lacks its required inputs and no trigger reaches it.
    const card = () => el.querySelector('[data-node="change"]') as HTMLElement;
    expect(card().getAttribute('data-marks')).toBe('problem');
    expect(card().getAttribute('aria-label')).toContain('workflowDesigner.problem.required');
    expect(el.querySelector('[data-testid="wd-problems"]')?.textContent).toContain('workflowDesigner.problem.unreachable');

    select('change');
    output('make', 'record').click();
    fixture.detectChanges();
    input('record_id').click();
    fixture.detectChanges();
    output('t', 'out').click();
    fixture.detectChanges();
    input('data').click();
    fixture.detectChanges();
    expect(c.problems()).toEqual([]);
    expect(card().getAttribute('data-marks')).toBeNull();
    expect(el.querySelector('[data-testid="wd-problems"]')).toBeNull();
  });

  it('a problem in the list selects its node', () => {
    const { fixture, el, c } = setup();
    (el.querySelector('[data-testid="wd-problem"][data-node="change"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(c.selected()).toBe('change');
  });

  it('a published version has passed: nothing is marked', () => {
    const { el, c } = setup(FLOW, 'published');
    expect(c.problems()).toEqual([]);
    expect(el.querySelector('[data-testid="wd-problem-count"]')).toBeNull();
  });
});

describe('publishProblems', () => {
  const ok: GraphDoc = {
    nodes: [node('t', 'trigger'), node('w', 'wait')],
    edges: [edge('t', 'out', 'w', 'in')],
  };

  it('passes a sound flow', () => {
    expect(publishProblems(ok, NODE_TYPES)).toEqual([]);
  });

  it('refuses an empty flow and a flow with no trigger', () => {
    expect(keysOf({ nodes: [], edges: [] }, null)).toEqual(['empty']);
    expect(keysOf({ nodes: [node('w', 'wait')], edges: [] }, null)).toEqual(['noEntry']);
  });

  it('refuses a duplicate id and an unknown type', () => {
    expect(keysOf({ nodes: [...ok.nodes, node('w', 'wait')], edges: ok.edges }, 'w')).toContain('duplicateId');
    expect(keysOf({ nodes: [...ok.nodes, node('x', 'nonsense')], edges: ok.edges }, 'x')).toContain('unknownType');
  });

  it('refuses edges to nothing, to a missing port, and of the wrong type', () => {
    expect(keysOf({ ...ok, edges: [...ok.edges, edge('t', 'out', 'gone', 'in')] }, 't')).toContain('edgeUnknown');
    expect(keysOf({ ...ok, edges: [edge('t', 'nope', 'w', 'in')] }, 't')).toContain('noOutput');
    expect(keysOf({ ...ok, edges: [edge('t', 'out', 'w', 'nope')] }, 'w')).toContain('noInput');
    const typed: GraphDoc = {
      nodes: [node('t', 'trigger'), node('m', 'create_record'), node('u', 'update_record')],
      edges: [edge('t', 'out', 'm', 'data'), edge('m', 'record', 'u', 'data'), edge('m', 'record', 'u', 'record_id')],
    };
    expect(keysOf(typed, 'u')).toEqual(['portType']);
  });

  it('accepts an error port and refuses one on a trigger', () => {
    const doc: GraphDoc = {
      nodes: [node('t', 'trigger'), node('w', 'wait'), node('x', 'wait')],
      edges: [edge('t', 'out', 'w', 'in'), edge('w', 'on_error', 'x', 'in')],
    };
    expect(publishProblems(doc, NODE_TYPES)).toEqual([]);
    expect(keysOf({ ...ok, edges: [edge('t', 'on_error', 'w', 'in')] }, 't')).toContain('noOutput');
  });

  it('refuses an input into a trigger, a missing required input and a loop', () => {
    expect(keysOf({ ...ok, edges: [...ok.edges, edge('w', 'out', 't', 'in')] }, 't')).toContain('entryInbound');
    const required: GraphDoc = { nodes: [node('t', 'trigger'), node('c', 'condition')], edges: [] };
    expect(keysOf(required, 'c')).toContain('required');
    const loop: GraphDoc = {
      nodes: [node('t', 'trigger'), node('a', 'wait'), node('b', 'wait')],
      edges: [edge('t', 'out', 'a', 'in'), edge('a', 'out', 'b', 'in'), edge('b', 'out', 'a', 'in')],
    };
    expect(keysOf(loop, 'a')).toEqual(['cycle']);
    expect(keysOf(loop, 'b')).toEqual(['cycle']);
  });

  it('refuses a step no trigger reaches and a split with no join', () => {
    expect(keysOf({ nodes: [...ok.nodes, node('lost', 'wait')], edges: ok.edges }, 'lost')).toEqual(['unreachable']);
    const split: GraphDoc = {
      nodes: [node('t', 'trigger'), node('s', 'split'), node('w', 'wait')],
      edges: [edge('t', 'out', 's', 'in'), edge('s', 'out', 'w', 'in')],
    };
    expect(keysOf(split, 's')).toEqual(['split']);
    const joined: GraphDoc = {
      nodes: [...split.nodes, node('j', 'join')],
      edges: [...split.edges, edge('w', 'out', 'j', 'in')],
    };
    expect(publishProblems(joined, NODE_TYPES)).toEqual([]);
  });

  it('checks the settings publishing checks', () => {
    const one = (n: GraphDocNode) => keysOf({
      nodes: [node('t', 'trigger'), n],
      edges: n.type === 'for_each' ? [edge('t', 'out', n.id, 'items')] : n.type === 'map' ? [edge('t', 'out', n.id, 'in')] : [edge('t', 'out', n.id, 'params')],
    }, n.id);
    expect(one(node('f', 'for_each'))).toEqual(['forEachFlow']);
    expect(one(node('f', 'for_each', { definition_logicalname: 'child', batch_size: 101 }))).toEqual(['forEachBatch']);
    expect(one(node('f', 'for_each', { definition_logicalname: 'child', batch_size: 100 }))).toEqual([]);
    expect(one(node('f', 'for_each', { definition_logicalname: ' ' }))).toEqual([]);
    expect(one(node('c', 'connector', { system: 'erp' }))).toEqual(['connector']);
    expect(one(node('c', 'connector', { system: 'erp', operation: ' send ' }))).toEqual([]);
    expect(one(node('m', 'map'))).toEqual(['map']);
    expect(one(node('m', 'map', { mapping: { name: '/customer/name' } }))).toEqual([]);
    const rule = (value: unknown) => keysOf({
      nodes: [node('t', 'trigger'), node('m', 'create_record'), node('u', 'update_record', { on_conflict: value })],
      edges: [edge('t', 'out', 'm', 'data'), edge('m', 'record', 'u', 'record_id'), edge('t', 'out', 'u', 'data')],
    }, 'u');
    expect(rule('merge')).toEqual([]);
    expect(rule(null)).toEqual([]);
    expect(rule('whatever')).toEqual(['onConflict']);
  });

  it('checks a mapping as the map node does', () => {
    const mapping = (m: unknown, each?: unknown) => mapConfigOk({ mapping: m, each });
    expect(mapping({ a: '' })).toBe(true);
    expect(mapping({ 'a.b': { from: '/x', default: 1 } })).toBe(true);
    expect(mapping({ a: { value: 1 } })).toBe(true);
    expect(mapping({})).toBe(false);
    expect(mapping([])).toBe(false);
    expect(mapping({ 'a..b': '/x' })).toBe(false);
    expect(mapping({ a: 'x' })).toBe(false);
    expect(mapping({ a: 1 })).toBe(false);
    expect(mapping({ a: { value: 1, extra: 2 } })).toBe(false);
    expect(mapping({ a: { from: 'x' } })).toBe(false);
    expect(mapping({ a: '/x' }, '/items')).toBe(true);
    expect(mapping({ a: '/x' }, 'items')).toBe(false);
  });
});
