import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { Subject, of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import { type GraphDoc, type GraphDocNode } from '@attome/xrm/canvas';

import { type VersionSummary, WorkflowAdminService } from '../services/workflow-admin.service';
import { stepOrder } from './step-list.component';
import { defaultBase, diffGraphs } from './version-diff.component';
import { WorkflowDesignerComponent } from './workflow-designer.component';

// M2-T4: compare two versions (nodes and settings), and phones open a step list.

function node(id: string, type: string, config: Record<string, unknown> = {}, x = 0): GraphDocNode {
  return { id, type, config, ports: { x, y: 0 } };
}
const edge = (from_node: string, from_port: string, to_node: string, to_port: string) =>
  ({ from_node, from_port, to_node, to_port });
const summary = (id: string, version_number: number): VersionSummary =>
  ({ id, version_number, status: 'draft', published_at: null, row_version: 1 });

const OLD: GraphDoc = {
  nodes: [node('t', 'trigger'), node('hook', 'webhook', { url: 'https://a.test', retries: 1 }), node('gone', 'wait')],
  edges: [edge('t', 'out', 'hook', 'body'), edge('hook', 'response', 'gone', 'in')],
};
const NEW: GraphDoc = {
  nodes: [node('t', 'trigger', {}, 500), node('hook', 'webhook', { url: 'https://b.test', retries: 1 }), node('fresh', 'wait')],
  edges: [edge('t', 'out', 'hook', 'body'), edge('hook', 'response', 'fresh', 'in')],
};

function setup(graph: GraphDoc = NEW, others: Record<string, GraphDoc> = { v1: OLD }) {
  const version = (id: string, g: GraphDoc) => ({
    id, definition_id: 'd1', version_number: id === 'v2' ? 2 : 1, graph: g, status: 'draft', published_at: null,
    row_version: 1, created_at: '2026-11-03T00:00:00Z',
  });
  const svc = {
    getVersion: vi.fn((_d: string, id: string) => of(id === 'v2' ? version('v2', graph) : version(id, others[id]))),
    getDefinition: vi.fn(() => of({
      id: 'd1', logicalname: 'flow',
      versions: [summary('v2', 2), ...Object.keys(others).map((id, i) => summary(id, i + 1))],
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
  fixture.componentRef.setInput('versionId', 'v2');
  fixture.detectChanges();
  return { fixture, el: fixture.nativeElement as HTMLElement, c: fixture.componentInstance, svc };
}

describe('diffGraphs', () => {
  it('lists added, removed and changed nodes with their settings, and connections', () => {
    const d = diffGraphs(OLD, NEW);
    expect(d.added.map(n => n.id)).toEqual(['fresh']);
    expect(d.removed.map(n => n.id)).toEqual(['gone']);
    expect(d.changed).toEqual([{
      id: 'hook', type: 'webhook', typeBefore: null,
      settings: [{ key: 'url', before: 'https://a.test', after: 'https://b.test' }],
    }]);
    expect(d.edgesAdded).toEqual([edge('hook', 'response', 'fresh', 'in')]);
    expect(d.edgesRemoved).toEqual([edge('hook', 'response', 'gone', 'in')]);
  });

  it('a move, groups and notes are no difference, nor is the order of a setting\'s keys', () => {
    const a: GraphDoc = { nodes: [node('m', 'map', { mapping: { a: '/a', b: '/b' } }, 0)], edges: [] };
    const b: GraphDoc = {
      nodes: [node('m', 'map', { mapping: { b: '/b', a: '/a' } }, 400)], edges: [],
      groups: [{ id: 'g', label: 'x', nodes: ['m'] }], notes: [{ id: 'n', text: 'y', x: 0, y: 0 }],
    };
    const d = diffGraphs(a, b);
    expect([d.added, d.removed, d.changed, d.edgesAdded, d.edgesRemoved].flat()).toEqual([]);
  });

  it('reports a setting removed and a type changed', () => {
    const d = diffGraphs(
      { nodes: [node('x', 'wait', { minutes: 5 })], edges: [] },
      { nodes: [node('x', 'webhook')], edges: [] },
    );
    expect(d.changed[0].typeBefore).toBe('wait');
    expect(d.changed[0].settings).toEqual([{ key: 'minutes', before: 5, after: undefined }]);
  });
});

describe('defaultBase', () => {
  it('takes the version before this one, else any other', () => {
    const all = [summary('v1', 1), summary('v2', 2), summary('v3', 3)];
    expect(defaultBase(all, 'v2')?.id).toBe('v1');
    expect(defaultBase(all, 'v1')?.id).toBe('v3');
    expect(defaultBase([summary('v1', 1)], 'v1')).toBeNull();
  });
});

describe('comparing in the designer', () => {
  beforeEach(() => TestBed.resetTestingModule());

  it('compares with the version before, and with another when picked', () => {
    const { fixture, el, svc } = setup(NEW, { v1: OLD, v0: NEW });
    expect(svc.getDefinition).not.toHaveBeenCalled();
    (el.querySelector('[data-testid="wd-compare"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(svc.getVersion).toHaveBeenCalledWith('d1', 'v1');
    expect(el.querySelector('[data-testid="vd-added"]')?.textContent).toContain('fresh');
    expect(el.querySelector('[data-testid="vd-removed"]')?.textContent).toContain('gone');
    expect(el.querySelector('[data-testid="vd-setting"]')?.textContent).toContain('https://b.test');

    const select = el.querySelector('[data-testid="vd-base"]') as HTMLSelectElement;
    select.value = 'v0';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="vd-same"]')).toBeTruthy();

    (el.querySelector('[data-testid="vd-close"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="version-diff"]')).toBeNull();
  });

  it('shows the last version picked, whichever answer arrives first', () => {
    const { fixture, el, svc } = setup(NEW, { v1: OLD, v0: NEW });
    const slow = new Subject<unknown>();
    const fast = new Subject<unknown>();
    (el.querySelector('[data-testid="wd-compare"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    const version = (graph: GraphDoc) => ({ graph });
    svc.getVersion.mockReturnValueOnce(slow as never).mockReturnValueOnce(fast as never);
    const select = el.querySelector('[data-testid="vd-base"]') as HTMLSelectElement;
    select.value = 'v1';
    select.dispatchEvent(new Event('change'));
    select.value = 'v0';
    select.dispatchEvent(new Event('change'));
    fast.next(version(NEW));
    slow.next(version(OLD));
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="vd-same"]')).toBeTruthy();
  });

  it('says when there is nothing to compare with', () => {
    const { fixture, el } = setup(NEW, {});
    (el.querySelector('[data-testid="wd-compare"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="vd-only"]')).toBeTruthy();
  });
});

describe('the step list', () => {
  beforeEach(() => TestBed.resetTestingModule());
  afterEach(() => vi.unstubAllGlobals());

  function asPhone(matches: boolean) {
    vi.stubGlobal('matchMedia', vi.fn((query: string) => ({ matches: matches && query.includes('max-width'), media: query })));
  }

  it('orders steps as they run, keeping a looped step', () => {
    const doc: GraphDoc = {
      nodes: [node('later', 'wait'), node('t', 'trigger'), node('first', 'wait')],
      edges: [edge('t', 'out', 'first', 'in'), edge('first', 'out', 'later', 'in')],
    };
    expect(stepOrder(doc).map(n => n.id)).toEqual(['t', 'first', 'later']);
    const loop: GraphDoc = {
      nodes: [node('t', 'trigger'), node('a', 'wait'), node('b', 'wait')],
      edges: [edge('t', 'out', 'a', 'in'), edge('a', 'out', 'b', 'in'), edge('b', 'out', 'a', 'in')],
    };
    expect(stepOrder(loop).map(n => n.id).sort()).toEqual(['a', 'b', 't']);
  });

  it('a phone opens the step list, and its steps open their settings', () => {
    asPhone(true);
    const { fixture, el, c } = setup();
    expect(c.view()).toBe('steps');
    expect(el.querySelector('[data-testid="step-list"]')).toBeTruthy();
    const items = el.querySelectorAll('[data-testid="step-item"]');
    expect([...items].map(i => i.getAttribute('data-node'))).toEqual(['t', 'hook', 'fresh']);
    (el.querySelector('[data-testid="step-item"][data-node="hook"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(c.selected()).toBe('hook');
    expect(el.querySelector('[data-testid="wd-settings"] [data-field="url"]')).toBeTruthy();
    // The canvas stays mounted, so a setting changed here is still an undoable edit.
    const url = el.querySelector('[data-testid="wd-settings"] [data-field="url"]') as HTMLInputElement;
    url.value = 'https://c.test';
    url.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(c.current().nodes[1].config?.['url']).toBe('https://c.test');
  });

  it('a wider screen opens the canvas, and either can switch', () => {
    asPhone(false);
    const { fixture, el, c } = setup();
    expect(c.view()).toBe('canvas');
    expect(el.querySelector('[data-testid="step-list"]')).toBeNull();
    (el.querySelector('[data-testid="wd-view-steps"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="step-list"]')).toBeTruthy();
  });

  it('shows a step\'s problem in the list', () => {
    asPhone(true);
    const { el } = setup({ nodes: [node('t', 'trigger'), node('c', 'condition')], edges: [] });
    const item = el.querySelector('[data-testid="step-item"][data-node="c"]') as HTMLElement;
    expect(item.querySelector('[data-testid="step-note"]')?.textContent).toContain('workflowDesigner.problem.required');
  });
});
