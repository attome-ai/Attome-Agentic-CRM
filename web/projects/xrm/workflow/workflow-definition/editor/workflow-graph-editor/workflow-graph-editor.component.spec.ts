import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { EMPTY, of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import { Graph, VersionDetail, WorkflowAdminService } from '../../../services/workflow-admin.service';
import { WorkflowGraphEditorComponent } from './workflow-graph-editor.component';

// Covers the inspector's generated per-node-type config form. The schema it
// renders from is pinned to the Rust executors by
// node-config-schema.lockstep.spec.ts; what is asserted here is the editing
// behaviour that decides whether the resulting `graph` JSON is one the
// backend will actually run.

function version(graph: Graph, status = 'draft'): VersionDetail {
  return {
    id: 'v1', definition_id: 'd1', version_number: 1, graph, status,
    published_at: null, row_version: 1, created_at: '2026-08-09T00:00:00Z',
  };
}

function editor(graph: Graph, status = 'draft') {
  TestBed.configureTestingModule({
    imports: [WorkflowGraphEditorComponent],
    providers: [
      provideRouter([]),
      {
        provide: WorkflowAdminService,
        useValue: {
          getVersion:      vi.fn(() => of(version(graph, status))),
          listDefinitions: vi.fn(() => of([{ logicalname: 'onboarding' }])),
        },
      },
      { provide: AdminService, useValue: { listEntities: vi.fn(() => of([{ logicalname: 'account' }])) } },
      { provide: LangService, useValue: { translate: (key: string) => key } },
    ],
  });
  const fixture = TestBed.createComponent(WorkflowGraphEditorComponent);
  fixture.componentRef.setInput('definitionId', 'd1');
  fixture.componentRef.setInput('versionId', 'v1');
  fixture.detectChanges();
  return fixture.componentInstance;
}

function node(id: string, type: string, config: Record<string, unknown> = {}) {
  return { id, type, config, ports: { x: 0, y: 0 } };
}

function configOf(c: WorkflowGraphEditorComponent, id: string) {
  return c.graph().nodes.find(n => n.id === id)?.config;
}

describe('WorkflowGraphEditorComponent config form', () => {
  beforeEach(() => TestBed.resetTestingModule());

  it('offers each node type only its own fields', () => {
    const c = editor({ nodes: [node('w1', 'webhook'), node('c1', 'condition')], edges: [] });

    c.select('w1');
    expect(c.visibleConfigFields().map(f => f.key)).toEqual(['url', 'method']);

    c.select('c1');
    expect(c.visibleConfigFields().map(f => f.key)).toEqual(['field', 'op', 'value']);
  });

  it('shows a select as the executor default until it is set explicitly', () => {
    const c = editor({ nodes: [node('w1', 'webhook')], edges: [] });
    c.select('w1');

    const method = c.visibleConfigFields().find(f => f.key === 'method')!;
    // Displayed as POST (what execute_webhook falls back to) but not written
    // into the graph — an untouched field must not manufacture config.
    expect(c.stringValue(method)).toBe('POST');
    expect(configOf(c, 'w1')).toEqual({});
  });

  it('clearing a field deletes the key rather than storing an empty string', () => {
    const c = editor({ nodes: [node('a1', 'approval', { action_type: 'custom' })], edges: [] });
    c.select('a1');

    c.setConfig('action_type', undefined);

    expect(configOf(c, 'a1')).toEqual({});
    expect(c.dirty()).toBe(true);
  });

  it('gates a showIf field on the gating field\'s effective value', () => {
    const c = editor({ nodes: [node('c1', 'condition')], edges: [] });
    c.select('c1');

    // Default op is `eq`, which compares against a literal.
    expect(c.visibleConfigFields().map(f => f.key)).toContain('value');

    // `truthy` reads no literal, so the field must disappear.
    c.setConfig('op', 'truthy');
    expect(c.visibleConfigFields().map(f => f.key)).not.toContain('value');
  });

  it('preserves config keys the schema does not describe', () => {
    const c = editor({ nodes: [node('w1', 'webhook', { url: 'https://x.test', headers: { a: '1' } })], edges: [] });
    c.select('w1');

    expect(c.extraConfigKeys()).toEqual(['headers']);

    c.setConfig('method', 'PUT');

    expect(configOf(c, 'w1')).toEqual({ url: 'https://x.test', headers: { a: '1' }, method: 'PUT' });
  });

  it('parses a json field on blur and reports invalid JSON without writing it', () => {
    const c = editor({ nodes: [node('t1', 'trigger')], edges: [] });
    c.select('t1');

    c.setJsonBuffer('condition', '{ "status": ');
    c.applyJsonField('condition');
    expect(c.jsonError()['condition']).toBeTruthy();
    expect(configOf(c, 't1')).toEqual({});

    c.setJsonBuffer('condition', '{ "status": "new" }');
    c.applyJsonField('condition');
    expect(c.jsonError()['condition']).toBe('');
    expect(configOf(c, 't1')).toEqual({ condition: { status: 'new' } });
  });

  it('flags a required key the executor would fail on', () => {
    const c = editor({ nodes: [node('s1', 'sub_workflow')], edges: [] });
    c.select('s1');

    const f = c.visibleConfigFields()[0];
    expect(c.isMissingRequired(f)).toBe(true);

    c.setConfig('definition_logicalname', 'onboarding');
    expect(c.isMissingRequired(f)).toBe(false);
  });

  it('reseeds the form when the selection moves to another node', () => {
    const c = editor({
      nodes: [node('t1', 'trigger', { condition: { status: 'new' } }), node('t2', 'trigger')],
      edges: [],
    });

    c.select('t1');
    expect(c.jsonBuffer('condition')).toContain('"status"');

    // The second node's buffer must not inherit the first node's text.
    c.select('t2');
    expect(c.jsonBuffer('condition')).toBe('');
  });

  it('refuses config edits on a published (read-only) version', () => {
    const c = editor({ nodes: [node('w1', 'webhook')], edges: [] }, 'published');
    c.select('w1');

    c.setConfig('url', 'https://x.test');

    expect(configOf(c, 'w1')).toEqual({});
    expect(c.dirty()).toBe(false);
  });

  it('deletes the selected node on Delete, with its edges', () => {
    const c = editor({
      nodes: [node('t1', 'trigger'), node('w1', 'webhook')],
      edges: [{ from_node: 't1', from_port: 'out', to_node: 'w1', to_port: 'in' }],
    });
    c.select('w1');

    c.onWindowKeyDown(new KeyboardEvent('keydown', { key: 'Delete' }));

    expect(c.graph().nodes.map(n => n.id)).toEqual(['t1']);
    expect(c.graph().edges).toEqual([]);
    expect(c.selectedNodeId()).toBeNull();
  });

  it('ignores Delete while a text control has focus', () => {
    const c = editor({ nodes: [node('w1', 'webhook')], edges: [] });
    c.select('w1');

    // Backspacing inside a config input must edit the text, not eat the node.
    const typing = new KeyboardEvent('keydown', { key: 'Backspace' });
    Object.defineProperty(typing, 'target', { value: document.createElement('input') });
    c.onWindowKeyDown(typing);

    expect(c.graph().nodes).toHaveLength(1);
  });

  it('ignores Delete on a published (read-only) version', () => {
    const c = editor({ nodes: [node('w1', 'webhook')], edges: [] }, 'published');
    c.select('w1');

    c.onWindowKeyDown(new KeyboardEvent('keydown', { key: 'Delete' }));

    expect(c.graph().nodes).toHaveLength(1);
    expect(c.dirty()).toBe(false);
  });

  it('still configures nodes when the autocomplete sources are unavailable', () => {
    TestBed.configureTestingModule({
      imports: [WorkflowGraphEditorComponent],
      providers: [
        provideRouter([]),
        {
          provide: WorkflowAdminService,
          useValue: {
            getVersion:      vi.fn(() => of(version({ nodes: [node('r1', 'create_record')], edges: [] }))),
            listDefinitions: vi.fn(() => EMPTY),
          },
        },
        { provide: AdminService, useValue: { listEntities: vi.fn(() => EMPTY) } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(WorkflowGraphEditorComponent);
    fixture.componentRef.setInput('definitionId', 'd1');
    fixture.componentRef.setInput('versionId', 'v1');
    fixture.detectChanges();

    const c = fixture.componentInstance;
    c.select('r1');
    expect(c.entityNames()).toEqual([]);

    c.setConfig('entity', 'account');
    expect(configOf(c, 'r1')).toEqual({ entity: 'account' });
  });
});

// Wiring is mouse-driven: a port is both the drag handle and the drop target,
// and where the button comes up decides whether an edge is created, re-routed,
// or deleted. What is asserted here is that sequence of raw events, since a
// half-handled mouseup is exactly how "drag the end off to delete it" silently
// stops working.

describe('WorkflowGraphEditorComponent wiring', () => {
  beforeEach(() => TestBed.resetTestingModule());

  const edge = (from: string, fromPort: string, to: string, toPort: string) =>
    ({ from_node: from, from_port: fromPort, to_node: to, to_port: toPort });

  /** Press a port, release over another (or over nothing, for `undefined`). */
  function dragPort(
    c: WorkflowGraphEditorComponent,
    down: [string, string, boolean],
    up?: [string, string, boolean],
  ): void {
    c.onPortMouseDown(new MouseEvent('mousedown'), ...down);
    if (up) c.onPortMouseUp(new MouseEvent('mouseup'), ...up);
    c.onWindowMouseUp();   // always fires — the window sees every release
  }

  function graph() {
    return {
      nodes: [node('t1', 'trigger'), node('c1', 'condition'), node('w1', 'webhook')],
      edges: [],
    };
  }

  it('wires an edge when an output is dragged onto an input', () => {
    const c = editor(graph());

    dragPort(c, ['t1', 'out', false], ['c1', 'value', true]);

    expect(c.graph().edges).toEqual([edge('t1', 'out', 'c1', 'value')]);
    expect(c.dirty()).toBe(true);
    expect(c.pendingEdge()).toBeNull();
  });

  it('wires the same edge when the drag runs backwards, input to output', () => {
    const c = editor(graph());

    dragPort(c, ['c1', 'value', true], ['t1', 'out', false]);

    expect(c.graph().edges).toEqual([edge('t1', 'out', 'c1', 'value')]);
  });

  it('deletes the edge when its input end is dragged onto empty canvas', () => {
    const c = editor({ ...graph(), edges: [edge('t1', 'out', 'c1', 'value')] });

    // Grab the wired input, release over nothing.
    dragPort(c, ['c1', 'value', true]);

    expect(c.graph().edges).toEqual([]);
    expect(c.pendingEdge()).toBeNull();
    expect(c.dirty()).toBe(true);
  });

  it('re-routes rather than duplicates when a wired input is dropped on another input', () => {
    const c = editor({ ...graph(), edges: [edge('t1', 'out', 'c1', 'value')] });

    dragPort(c, ['c1', 'value', true], ['w1', 'body', true]);

    expect(c.graph().edges).toEqual([edge('t1', 'out', 'w1', 'body')]);
  });

  it('puts a detached edge back when the drag is abandoned with Escape', () => {
    const c = editor({ ...graph(), edges: [edge('t1', 'out', 'c1', 'value')] });

    c.onPortMouseDown(new MouseEvent('mousedown'), 'c1', 'value', true);
    expect(c.graph().edges).toEqual([]);          // detached while in flight

    c.onWindowKeyDown(new KeyboardEvent('keydown', { key: 'Escape' }));

    expect(c.graph().edges).toEqual([edge('t1', 'out', 'c1', 'value')]);
    expect(c.pendingEdge()).toBeNull();
  });

  it('still wires by clicking one port and then the other', () => {
    const c = editor(graph());

    // Press and release on the same port is a click: the wire stays armed.
    c.onPortMouseDown(new MouseEvent('mousedown'), 't1', 'out', false);
    c.onPortMouseUp(new MouseEvent('mouseup'), 't1', 'out', false);
    c.onWindowMouseUp();
    expect(c.pendingEdge()).not.toBeNull();

    c.onPortMouseDown(new MouseEvent('mousedown'), 'c1', 'value', true);
    c.onPortMouseUp(new MouseEvent('mouseup'), 'c1', 'value', true);
    c.onWindowMouseUp();

    expect(c.graph().edges).toEqual([edge('t1', 'out', 'c1', 'value')]);
  });

  it('refuses a self-loop and a duplicate of an edge that already exists', () => {
    const c = editor({ ...graph(), edges: [edge('t1', 'out', 'c1', 'value')] });

    dragPort(c, ['c1', 'true', false], ['c1', 'value', true]);      // self-loop
    dragPort(c, ['t1', 'out', false], ['c1', 'value', true]);       // already wired
    dragPort(c, ['t1', 'out', false], ['w1', 'body', true]);          // ...and a real one

    expect(c.graph().edges).toEqual([
      edge('t1', 'out', 'c1', 'value'),
      edge('t1', 'out', 'w1', 'body'),
    ]);
  });

  it('does not wire or unwire anything on a published (read-only) version', () => {
    const c = editor({ ...graph(), edges: [edge('t1', 'out', 'c1', 'value')] }, 'published');

    dragPort(c, ['t1', 'out', false], ['w1', 'body', true]);
    dragPort(c, ['c1', 'value', true]);

    expect(c.graph().edges).toEqual([edge('t1', 'out', 'c1', 'value')]);
    expect(c.dirty()).toBe(false);
  });

  it('refuses a drop whose port types the backend validator would reject', () => {
    // `record` is record_id, `body` is json — attome_workflow::graph::validate
    // rejects that edge at publish, so the canvas declines the drop instead.
    const c = editor({
      nodes: [node('r1', 'create_record'), node('w1', 'webhook')],
      edges: [],
    });

    c.onPortMouseDown(new MouseEvent('mousedown'), 'r1', 'record', false);
    expect(c.isDropTarget('w1', 'body', true)).toBe(false);

    c.onPortMouseUp(new MouseEvent('mouseup'), 'w1', 'body', true);
    c.onWindowMouseUp();

    expect(c.graph().edges).toEqual([]);
  });

  it('lights up only the ports the wire in flight can land on', () => {
    const c = editor(graph());

    c.onPortMouseDown(new MouseEvent('mousedown'), 't1', 'out', false);

    expect(c.isDropTarget('c1', 'value', true)).toBe(true);   // another node's input
    expect(c.isDropTarget('t1', 'out', false)).toBe(false);   // the anchor itself
    expect(c.isDropTarget('c1', 'true', false)).toBe(false);  // an output
  });
});

// The palette is gone: nodes are added from the double-click picker or from
// the `+` beside an output port, which is also the only path that wires the
// new node as it creates it.

describe('WorkflowGraphEditorComponent node-type picker', () => {
  beforeEach(() => TestBed.resetTestingModule());

  /** The picker only opens for a double-click that landed on the canvas
   *  itself — a double-click on a node is a node gesture. */
  function dblclick(c: WorkflowGraphEditorComponent, onCanvas = true): void {
    const evt = new MouseEvent('dblclick');
    const target = onCanvas ? document.querySelector('.canvas') : document.createElement('div');
    Object.defineProperty(evt, 'target', { value: target });
    c.openCanvasMenu(evt);
  }

  it('opens on a canvas double-click and adds the chosen type there', () => {
    const c = editor({ nodes: [], edges: [] });

    dblclick(c);
    expect(c.typeMenu()).not.toBeNull();
    expect(c.menuOptions().length).toBe(17);   // every node type, nothing wired yet (incl. M06's split/join, A18's restore, A15's duplicate check, M11's assign, E8-T2's module step, M1-T4's for each)

    c.chooseType('condition');

    expect(c.graph().nodes).toHaveLength(1);
    expect(c.graph().nodes[0].type).toBe('condition');
    expect(c.selectedNodeId()).toBe(c.graph().nodes[0].id);
    expect(c.typeMenu()).toBeNull();
  });

  it('ignores a double-click that landed on a node', () => {
    const c = editor({ nodes: [node('t1', 'trigger')], edges: [] });

    dblclick(c, false);

    expect(c.typeMenu()).toBeNull();
  });

  it('filters the list by the search box', () => {
    const c = editor({ nodes: [], edges: [] });
    dblclick(c);

    c.menuFilter.set('record');

    expect(c.menuOptions().map(t => t.type)).toEqual(['create_record', 'update_record', 'restore_record']);
  });

  it('offers only types that accept the output the + was opened from', () => {
    const c = editor({ nodes: [node('r1', 'create_record')], edges: [] });

    // `record` is record_id: json-only inputs are not offered, and neither is
    // Trigger, which has no inputs at all.
    c.openOutputMenu(new MouseEvent('click'), 'r1', 'record');

    const offered = c.menuOptions().map(t => t.type);
    expect(offered).toContain('update_record');   // record_id input
    expect(offered).toContain('condition');       // any input
    expect(offered).not.toContain('webhook');     // json input
    expect(offered).not.toContain('trigger');     // no inputs
  });

  it('wires the node it creates from a + into the compatible input', () => {
    const c = editor({ nodes: [node('t1', 'trigger')], edges: [] });

    c.openOutputMenu(new MouseEvent('click'), 't1', 'out');
    c.chooseType('condition');

    const created = c.graph().nodes[1];
    expect(created.type).toBe('condition');
    expect(c.graph().edges).toEqual([
      { from_node: 't1', from_port: 'out', to_node: created.id, to_port: 'value' },
    ]);
    // Placed clear of its source rather than on top of it.
    expect(created.ports.x).toBeGreaterThan(c.graph().nodes[0].ports.x);
  });

  it('stacks each new node below the last instead of on top of it', () => {
    const c = editor({ nodes: [node('t1', 'trigger')], edges: [] });

    c.openOutputMenu(new MouseEvent('click'), 't1', 'out');
    c.chooseType('condition');
    c.openOutputMenu(new MouseEvent('click'), 't1', 'out');
    c.chooseType('webhook');

    const [, first, second] = c.graph().nodes;
    expect(second.ports.y).toBeGreaterThan(first.ports.y);
  });

  it('closes on Escape without adding anything, and Escape does not eat a wire', () => {
    const c = editor({ nodes: [node('t1', 'trigger')], edges: [] });

    dblclick(c);
    c.onWindowKeyDown(new KeyboardEvent('keydown', { key: 'Escape' }));

    expect(c.typeMenu()).toBeNull();
    expect(c.graph().nodes).toHaveLength(1);
  });

  it('adds nothing from the picker on a published (read-only) version', () => {
    const c = editor({ nodes: [node('t1', 'trigger')], edges: [] }, 'published');

    dblclick(c);
    c.openOutputMenu(new MouseEvent('click'), 't1', 'out');

    expect(c.typeMenu()).toBeNull();
    expect(c.graph().nodes).toHaveLength(1);
    expect(c.dirty()).toBe(false);
  });

  it('numbers nodes by position, closing the gap when one is deleted', () => {
    const c = editor({
      nodes: [node('t1', 'trigger'), node('c1', 'condition'), node('w1', 'webhook')],
      edges: [],
    });

    expect(c.nodeNumber('t1')).toBe(1);
    expect(c.nodeNumber('w1')).toBe(3);

    c.deleteNode('c1');

    // The badge is a label, not an identity — `w1` keeps its id and its edges.
    expect(c.nodeNumber('w1')).toBe(2);
  });
});

// The canvas has no scrollbars: a work surface larger than its frame is moved
// by dragging its background, so the clamping is what keeps a node from ending
// up somewhere the user cannot pan back to.

describe('WorkflowGraphEditorComponent canvas panning', () => {
  beforeEach(() => TestBed.resetTestingModule());

  /** jsdom lays nothing out, so the surface/frame sizes the clamp reads from
   *  are stubbed to the real CSS: a 2000×1400 surface in an 800×600 frame. */
  function sized(c: WorkflowGraphEditorComponent) {
    const surface = document.querySelector('.canvas') as HTMLElement;
    const frame   = document.querySelector('.canvas-wrap') as HTMLElement;
    Object.defineProperty(surface, 'offsetWidth',  { value: 2000, configurable: true });
    Object.defineProperty(surface, 'offsetHeight', { value: 1400, configurable: true });
    Object.defineProperty(frame,   'clientWidth',  { value: 800,  configurable: true });
    Object.defineProperty(frame,   'clientHeight', { value: 600,  configurable: true });
    return { c, surface };
  }

  function press(target: HTMLElement, button = 0): MouseEvent {
    const evt = new MouseEvent('mousedown', { button, clientX: 0, clientY: 0 });
    Object.defineProperty(evt, 'target', { value: target });
    return evt;
  }

  const move = (x: number, y: number) => new MouseEvent('mousemove', { clientX: x, clientY: y });

  it('moves the surface with the cursor when its background is dragged', () => {
    const { c, surface } = sized(editor({ nodes: [node('t1', 'trigger')], edges: [] }));

    c.onCanvasMouseDown(press(surface));
    expect(c.panning()).toBe(true);

    c.onWindowMouseMove(move(-120, -80));
    expect([c.panX(), c.panY()]).toEqual([-120, -80]);

    c.onWindowMouseUp();
    expect(c.panning()).toBe(false);
  });

  it('clamps the pan so the surface always covers the frame', () => {
    const { c, surface } = sized(editor({ nodes: [], edges: [] }));

    c.onCanvasMouseDown(press(surface));

    // Past the top-left corner of the surface — there is nothing there to show.
    c.onWindowMouseMove(move(400, 300));
    expect([c.panX(), c.panY()]).toEqual([0, 0]);

    // Past its bottom-right: stops with the far edge against the frame.
    c.onWindowMouseMove(move(-5000, -5000));
    expect([c.panX(), c.panY()]).toEqual([800 - 2000, 600 - 1400]);
  });

  it('does not pan when the press landed on a node rather than the background', () => {
    const { c } = sized(editor({ nodes: [node('t1', 'trigger')], edges: [] }));

    c.onCanvasMouseDown(press(document.createElement('div')));
    c.onWindowMouseMove(move(-120, -80));

    expect([c.panX(), c.panY()]).toEqual([0, 0]);
    expect(c.panning()).toBe(false);
  });

  it('scrolls the surface with the wheel instead of the page', () => {
    const { c } = sized(editor({ nodes: [], edges: [] }));

    const wheel = new WheelEvent('wheel', { deltaY: 120, cancelable: true });
    c.onCanvasWheel(wheel);

    expect(c.panY()).toBe(-120);
    expect(wheel.defaultPrevented).toBe(true);

    // Shift turns a vertical wheel into horizontal movement.
    c.onCanvasWheel(new WheelEvent('wheel', { deltaY: 60, shiftKey: true, cancelable: true }));
    expect(c.panX()).toBe(-60);
  });
});
