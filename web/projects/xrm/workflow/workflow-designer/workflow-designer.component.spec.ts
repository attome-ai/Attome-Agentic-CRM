import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import { GraphCanvasComponent, checkConnection, type GraphDoc } from '@attome/xrm/canvas';

import { Graph, NODE_TYPES, VersionDetail, WorkflowAdminService } from '../services/workflow-admin.service';
import { WorkflowDesignerComponent, paletteMatches, placedGraph } from './workflow-designer.component';

// M2-T1: the flow designer on the canvas engine's graph mode — typed ports
// checked while dragging, the palette and generated settings kept, groups,
// notes and the sub-flow jump.

function version(graph: Graph | GraphDoc, status = 'draft'): VersionDetail {
  return {
    id: 'v1', definition_id: 'd1', version_number: 3, graph, status,
    published_at: null, row_version: 7, created_at: '2026-11-03T00:00:00Z',
  };
}

function node(id: string, type: string, x = 0, y = 0, config: Record<string, unknown> = {}) {
  return { id, type, config, ports: { x, y } };
}

const FLOW: Graph = {
  nodes: [
    node('t', 'trigger', 40, 40),
    node('make', 'create_record', 320, 40, { entity: 'account' }),
    node('change', 'update_record', 600, 40),
  ],
  edges: [{ from_node: 't', from_port: 'out', to_node: 'make', to_port: 'data' }],
};

function setup(graph: Graph | GraphDoc = FLOW, status = 'draft') {
  const svc = {
    getVersion: vi.fn(() => of(version(graph, status))),
    listDefinitions: vi.fn(() => of([{ id: 'd2', logicalname: 'child_flow' }])),
    getDefinition: vi.fn(() => of({
      id: 'd2', logicalname: 'child_flow',
      versions: [
        { id: 'c1', version_number: 1, status: 'published', published_at: null, row_version: 1 },
        { id: 'c2', version_number: 2, status: 'draft', published_at: null, row_version: 1 },
      ],
    })),
    updateVersionGraph: vi.fn((_d: string, _v: string, body: { graph: unknown }) =>
      of({ ...version(body.graph as Graph), row_version: 8 })),
    publishVersion: vi.fn(() => of(version(graph, 'published'))),
  };
  TestBed.configureTestingModule({
    imports: [WorkflowDesignerComponent],
    providers: [
      provideRouter([]),
      { provide: WorkflowAdminService, useValue: svc },
      { provide: AdminService, useValue: { listEntities: vi.fn(() => of([{ logicalname: 'account' }])) } },
      { provide: LangService, useValue: { translate: (key: string) => key } },
    ],
  });
  const fixture = TestBed.createComponent(WorkflowDesignerComponent);
  fixture.componentRef.setInput('definitionId', 'd1');
  fixture.componentRef.setInput('versionId', 'v1');
  fixture.detectChanges();
  const el = fixture.nativeElement as HTMLElement;
  const canvas = () => fixture.debugElement.query(d => d.componentInstance instanceof GraphCanvasComponent)
    .componentInstance as GraphCanvasComponent;
  return { fixture, el, c: fixture.componentInstance, svc, canvas };
}

/** A pointer event, as a mouse event where the test DOM has no PointerEvent. */
function pointer(type: string, init: MouseEventInit = {}): Event {
  const Ctor = (globalThis as { PointerEvent?: typeof MouseEvent }).PointerEvent ?? MouseEvent;
  return new Ctor(type, init);
}

function port(el: HTMLElement, nodeId: string, side: 'in' | 'out', name: string): HTMLButtonElement {
  const card = el.querySelector(`[data-node="${nodeId}"]`) as HTMLElement;
  return card.querySelector(`[data-testid="graph-port-${side}"][data-port="${name}"]`) as HTMLButtonElement;
}

describe('WorkflowDesignerComponent', () => {
  beforeEach(() => TestBed.resetTestingModule());

  it('renders the flow\'s nodes as canvas cards and its edges as wires', () => {
    const { el } = setup();
    expect(el.querySelectorAll('[data-testid="graph-node"]').length).toBe(3);
    expect(el.querySelectorAll('[data-testid="graph-wire"]').length).toBe(1);
    // Ports carry their types.
    expect(port(el, 'make', 'out', 'record').textContent).toContain('record_id');
    expect(port(el, 'change', 'in', 'data').textContent).toContain('json');
  });

  it('checks typed ports while dragging and refuses an incompatible drop with the reason', () => {
    const { fixture, el, c } = setup();
    port(el, 'make', 'out', 'record').dispatchEvent(pointer('pointerdown', { bubbles: true, button: 0 }));
    fixture.detectChanges();
    // While dragging, the record_id input accepts and the json input does not.
    expect(port(el, 'change', 'in', 'record_id').classList).toContain('gc-port--ok');
    expect(port(el, 'change', 'in', 'data').classList).toContain('gc-port--no');
    port(el, 'change', 'in', 'data').dispatchEvent(pointer('pointerenter'));
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="graph-status"]')?.textContent).toContain('graphCanvas.refuse.type');
    // Dropped there: refused, no edge, the reason stays.
    port(el, 'change', 'in', 'data').dispatchEvent(pointer('pointerup', { bubbles: true }));
    fixture.detectChanges();
    expect(c.current().edges.length).toBe(1);
    expect(el.querySelector('[data-testid="graph-status"]')?.textContent).toContain('graphCanvas.refuse.type');
    // Dragged again onto the compatible input: the edge is made.
    port(el, 'make', 'out', 'record').dispatchEvent(pointer('pointerdown', { bubbles: true, button: 0 }));
    port(el, 'change', 'in', 'record_id').dispatchEvent(pointer('pointerup', { bubbles: true }));
    fixture.detectChanges();
    expect(c.current().edges).toContainEqual({ from_node: 'make', from_port: 'record', to_node: 'change', to_port: 'record_id' });
    expect(el.querySelectorAll('[data-testid="graph-wire"]').length).toBe(2);
  });

  it('connects by keyboard: an output, then an input', () => {
    const { fixture, el, c } = setup();
    port(el, 'make', 'out', 'record').dispatchEvent(new MouseEvent('click', { bubbles: true, detail: 0 }));
    fixture.detectChanges();
    expect(port(el, 'make', 'out', 'record').classList).toContain('gc-port--armed');
    port(el, 'change', 'in', 'record_id').dispatchEvent(new MouseEvent('click', { bubbles: true, detail: 0 }));
    fixture.detectChanges();
    expect(c.current().edges.length).toBe(2);
  });

  it('applies the engine\'s publish rules to a connection', () => {
    const doc = placedGraph(FLOW);
    // A trigger takes no input.
    expect(checkConnection(doc, NODE_TYPES, { node: 'make', port: 'record' }, { node: 't', port: 'in' })?.key)
      .toBe('graphCanvas.refuse.entry');
    // The same edge twice.
    expect(checkConnection(doc, NODE_TYPES, { node: 't', port: 'out' }, { node: 'make', port: 'data' })?.key)
      .toBe('graphCanvas.refuse.duplicate');
    // A loop back to the start of the chain.
    const looped = { ...doc, edges: [...doc.edges, { from_node: 'make', from_port: 'record', to_node: 'change', to_port: 'record_id' }] };
    expect(checkConnection(looped, NODE_TYPES, { node: 'change', port: 'on_error' }, { node: 'make', port: 'data' })?.key)
      .toBe('graphCanvas.refuse.cycle');
    // The error port is json, so it meets a json input.
    expect(checkConnection(doc, NODE_TYPES, { node: 'make', port: 'on_error' }, { node: 'change', port: 'data' })).toBeNull();
    // `any` meets every type.
    expect(checkConnection(doc, NODE_TYPES, { node: 't', port: 'out' }, { node: 'change', port: 'record_id' })).toBeNull();
  });

  it('keeps the palette and the generated settings form', () => {
    const { fixture, el, c } = setup();
    expect(paletteMatches(NODE_TYPES, 'webhook', t => t).map(k => k.type)).toEqual(['webhook']);
    c.query.set('webhook');
    fixture.detectChanges();
    const add = el.querySelectorAll('[data-testid="wd-add"]');
    expect(add.length).toBe(1);
    (add[0] as HTMLButtonElement).click();
    fixture.detectChanges();
    const added = c.current().nodes.at(-1);
    expect(added?.type).toBe('webhook');
    expect(c.selected()).toBe(added?.id);
    // The settings form is the node type's schema; a value lands in config.
    const url = el.querySelector('[data-testid="wd-settings"] [data-field="url"]') as HTMLInputElement;
    expect(url).toBeTruthy();
    url.value = 'https://hooks.example.test/x';
    url.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(c.current().nodes.at(-1)?.config?.['url']).toBe('https://hooks.example.test/x');
  });

  it('groups nodes, adds notes, undoes, and saves them with the graph', () => {
    const { fixture, el, c, svc, canvas } = setup();
    canvas().selectNode('t');
    canvas().selectNode('make', new MouseEvent('click', { ctrlKey: true }));
    fixture.detectChanges();
    (el.querySelector('[data-testid="graph-group"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(c.current().groups?.[0].nodes).toEqual(['t', 'make']);
    expect(el.querySelectorAll('[data-testid="graph-group-frame"]').length).toBe(1);
    (el.querySelector('[data-testid="graph-note"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    const note = el.querySelector('[data-testid="graph-note-text"]') as HTMLTextAreaElement;
    note.value = 'تأكد من البريد';
    note.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(c.current().notes?.[0].text).toBe('تأكد من البريد');
    (el.querySelector('[data-testid="graph-undo"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(c.current().notes?.[0].text).toBe('');
    (el.querySelector('[data-testid="graph-save"]') as HTMLButtonElement).click();
    const body = svc.updateVersionGraph.mock.calls[0][2] as { graph: GraphDoc; row_version: number };
    expect(body.row_version).toBe(7);
    expect(body.graph.groups?.[0].nodes).toEqual(['t', 'make']);
    expect(body.graph.notes?.length).toBe(1);
    expect(c.dirty()).toBe(false);
  });

  it('moves a node with the arrows and deletes it with its wires', () => {
    const { fixture, c, canvas } = setup();
    canvas().selectNode('make');
    canvas().onKey(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
    expect(c.current().nodes[1].ports.y).toBe(48);
    canvas().onKey(new KeyboardEvent('keydown', { key: 'Delete' }));
    fixture.detectChanges();
    expect(c.current().nodes.map(n => n.id)).toEqual(['t', 'change']);
    expect(c.current().edges).toEqual([]);
  });

  it('opens the flow a sub-flow node runs, on its draft', () => {
    const graph: Graph = { nodes: [node('t', 'trigger'), node('sub', 'sub_workflow', 300, 40, { definition_logicalname: 'child_flow' })], edges: [] };
    const { fixture, el } = setup(graph);
    const router = TestBed.inject(Router);
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    (el.querySelector('[data-testid="graph-open-subflow"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(navigate).toHaveBeenCalledWith(['/xrm/workflow/definitions', 'd2', 'versions', 'c2', 'design']);
  });

  it('shows a published version read-only', () => {
    const { el } = setup(FLOW, 'published');
    expect(el.querySelector('[data-testid="wd-add"]')).toBeNull();
    expect(el.querySelector('[data-testid="graph-save"]')).toBeNull();
    expect(port(el, 'make', 'out', 'record').disabled).toBe(true);
  });

  it('places nodes a graph left without a position', () => {
    const doc = placedGraph({ nodes: [{ id: 'a', type: 'trigger', config: {} }], edges: [] });
    expect(doc.nodes[0].ports).toEqual({ x: 40, y: 40 });
  });
});
