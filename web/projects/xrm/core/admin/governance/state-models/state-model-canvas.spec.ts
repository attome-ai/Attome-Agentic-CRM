import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { GraphCanvasComponent, checkConnection, outputsOf } from '@attome/xrm/canvas';
import { StateModelsService, type StateHistoryChange, type StateTransition } from '@attome/xrm/core/admin/data';

import {
  StateModelCanvasComponent, durationParts, layoutStates, stateGraph, stateKinds, stateStays, timeInState,
  transitionChanges,
} from './state-model-canvas.component';

// M8-T4: states and transitions as nodes and edges; a drawn connection and a
// deleted wire become transitions; a record's stays and time in each state.

const STATES = ['new', 'open', 'closed'];

function transition(from_state: string, to_state: string, id = `${from_state}-${to_state}`): StateTransition {
  return {
    id, model_ref: 'm1', from_state, to_state, name: id, required_privilege: null, guard_expression: null,
    entry_actions: [], exit_actions: [], display_order: 0, row_version: 1, owner_layer: 'project',
  } as StateTransition;
}

function change(at: string, old_value: string | null, new_value: string | null, masked = false): StateHistoryChange {
  return {
    audit_id: at, changed_on: at, operation: 'update', group_id: 'g', actor: 'user',
    fields: [{ field_name: 'status', masked, old_value, new_value }],
  } as StateHistoryChange;
}

function setup(svc: Partial<Record<'stateHistory', unknown>> = {}) {
  TestBed.configureTestingModule({
    imports: [StateModelCanvasComponent],
    providers: [
      { provide: StateModelsService, useValue: svc },
      { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
    ],
  });
  const fixture = TestBed.createComponent(StateModelCanvasComponent);
  fixture.componentRef.setInput('modelId', `m-${Math.random()}`);
  fixture.componentRef.setInput('entity', 'ticket');
  fixture.componentRef.setInput('field', 'status');
  fixture.componentRef.setInput('states', STATES);
  fixture.componentRef.setInput('transitions', [transition('new', 'open')]);
  fixture.componentRef.setInput('initial', 'new');
  fixture.detectChanges();
  const el = fixture.nativeElement as HTMLElement;
  const canvas = () => fixture.debugElement.query(d => d.componentInstance instanceof GraphCanvasComponent)
    .componentInstance as GraphCanvasComponent;
  return { fixture, el, c: fixture.componentInstance, canvas };
}

describe('StateModelCanvasComponent', () => {
  beforeEach(() => TestBed.resetTestingModule());

  it('draws the states as nodes and the transitions as edges, the initial state marked', () => {
    const { el } = setup();
    const cards = el.querySelectorAll('[data-testid="graph-node"]');
    expect([...cards].map(c => c.getAttribute('data-node'))).toEqual(STATES);
    expect(el.querySelectorAll('[data-testid="graph-wire"]').length).toBe(1);
    expect(el.querySelector('[data-node="new"]')?.getAttribute('data-marks')).toBe('initial');
    // The nodes are the field's options: no group, note or save here.
    expect(el.querySelector('[data-testid="graph-note"]')).toBeNull();
    expect(el.querySelector('[data-testid="graph-save"]')).toBeNull();
  });

  it('a drawn connection asks for a transition', () => {
    const { fixture, el, c } = setup();
    const added: { from: string; to: string }[] = [];
    c.addTransition.subscribe(a => added.push(a));
    const out = el.querySelector('[data-node="open"] [data-testid="graph-port-out"]') as HTMLButtonElement;
    out.dispatchEvent(new MouseEvent('click', { bubbles: true, detail: 0 }));
    fixture.detectChanges();
    (el.querySelector('[data-node="closed"] [data-testid="graph-port-in"]') as HTMLButtonElement)
      .dispatchEvent(new MouseEvent('click', { bubbles: true, detail: 0 }));
    expect(added).toEqual([{ from: 'open', to: 'closed' }]);
  });

  it('a record may go back to a state: the canvas allows the loop', () => {
    const { fixture, el, c } = setup();
    const added: { from: string; to: string }[] = [];
    c.addTransition.subscribe(a => added.push(a));
    (el.querySelector('[data-node="open"] [data-testid="graph-port-out"]') as HTMLButtonElement)
      .dispatchEvent(new MouseEvent('click', { bubbles: true, detail: 0 }));
    fixture.detectChanges();
    (el.querySelector('[data-node="new"] [data-testid="graph-port-in"]') as HTMLButtonElement)
      .dispatchEvent(new MouseEvent('click', { bubbles: true, detail: 0 }));
    expect(added).toEqual([{ from: 'open', to: 'new' }]);
    // The same connection is a loop on a flow's canvas.
    const doc = stateGraph(STATES, [transition('new', 'open')], 'new');
    expect(checkConnection(doc, stateKinds(STATES), { node: 'open', port: 'out' }, { node: 'new', port: 'in' })?.key)
      .toBe('graphCanvas.refuse.cycle');
  });

  it('a deleted wire asks to remove its transition; a state cannot be deleted', () => {
    const { c, canvas } = setup();
    const removed: StateTransition[] = [];
    c.removeTransition.subscribe(t => removed.push(t));
    canvas().selectNode('open');
    canvas().onKey(new KeyboardEvent('keydown', { key: 'Delete' }));
    expect(removed).toEqual([]);
    expect(canvas().stack().doc().nodes.length).toBe(3);
    canvas().selectEdge(0, new Event('click'));
    canvas().onKey(new KeyboardEvent('keydown', { key: 'Delete' }));
    expect(removed.map(t => t.id)).toEqual(['new-open']);
  });

  it('moving a state asks nothing of the server', () => {
    const { c, canvas } = setup();
    const asks: unknown[] = [];
    c.addTransition.subscribe(a => asks.push(a));
    c.removeTransition.subscribe(t => asks.push(t));
    canvas().selectNode('open');
    canvas().onKey(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
    expect(canvas().stack().doc().nodes[1].ports.y).toBeGreaterThan(0);
    expect(asks).toEqual([]);
  });

  it('lays out by distance from the initial state, the unconnected after', () => {
    const at = layoutStates(STATES, [transition('new', 'open')], 'new');
    expect(at.get('new')?.x).toBeLessThan(at.get('open')?.x ?? 0);
    expect(at.get('open')?.x).toBeLessThan(at.get('closed')?.x ?? 0);
  });

  it('keeps drawing a transition whose state the field no longer offers', () => {
    const doc = stateGraph(['new'], [transition('new', 'gone')], 'new');
    expect(doc.nodes.map(n => n.id)).toEqual(['new', 'gone']);
  });

  it('states have no error port', () => {
    expect(outputsOf(stateKinds(['new'])[0]).map(p => p.name)).toEqual(['out']);
  });

  it('compares a graph with the saved transitions', () => {
    const saved = [transition('new', 'open'), transition('open', 'closed')];
    const edge = (a: string, b: string) => ({ from_node: a, from_port: 'out', to_node: b, to_port: 'in' });
    expect(transitionChanges([edge('new', 'open'), edge('open', 'closed')], saved)).toEqual({ add: [], remove: [] });
    const asks = transitionChanges([edge('new', 'open'), edge('closed', 'new')], saved);
    expect(asks.add).toEqual([{ from: 'closed', to: 'new' }]);
    expect(asks.remove.map(t => t.id)).toEqual(['open-closed']);
  });

  it('works out stays and time in state from the field\'s history', () => {
    const now = Date.parse('2026-11-03T12:00:00Z');
    // The route answers newest first.
    const stays = stateStays([
      change('2026-11-03T00:00:00Z', 'new', 'open'),
      change('2026-11-02T00:00:00Z', 'open', 'new'),
      change('2026-11-01T00:00:00Z', 'draft', 'open'),
    ], 'status', now);
    expect(stays.map(s => s.state)).toEqual(['open', 'new', 'open']);
    expect(stays[0].to).toBe('2026-11-02T00:00:00Z');
    expect(stays[2].to).toBeNull();
    expect(stays[2].ms).toBe(12 * 3_600_000);
    expect(timeInState(stays)).toEqual([
      { state: 'open', ms: 36 * 3_600_000 },
      { state: 'new', ms: 24 * 3_600_000 },
    ]);
    expect(durationParts(36 * 3_600_000 + 5 * 60_000)).toEqual({ days: 1, hours: 12, minutes: 5 });
  });

  it('a masked change ends a stay and starts none', () => {
    const stays = stateStays([
      change('2026-11-01T00:00:00Z', 'a', 'open'),
      change('2026-11-02T00:00:00Z', null, null, true),
    ], 'status', Date.parse('2026-11-03T00:00:00Z'));
    expect(stays.map(s => [s.state, s.ms])).toEqual([['open', 24 * 3_600_000]]);
  });

  it('shows a record\'s history, and says when older changes are left out', () => {
    const stateHistory = vi.fn(() => of({ items: [change('2026-11-01T00:00:00Z', 'new', 'open')], next_cursor: 'more' }));
    const { fixture, el } = setup({ stateHistory });
    const box = el.querySelector('[data-testid="smc-record"]') as HTMLInputElement;
    box.value = 'r1';
    box.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (el.querySelector('[data-testid="smc-lookup"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(stateHistory).toHaveBeenCalledWith('ticket', 'r1', 'status');
    expect(el.querySelector('[data-testid="smc-totals"]')?.textContent).toContain('open');
    expect(el.querySelectorAll('[data-testid="smc-stays"] tbody tr').length).toBe(1);
    expect(el.querySelector('[data-testid="smc-truncated"]')).toBeTruthy();
  });

  it('leaves the canvas alone when the same states come again, and drops the history for another model', () => {
    const stateHistory = vi.fn(() => of({ items: [change('2026-11-01T00:00:00Z', 'new', 'open')], next_cursor: null }));
    const { fixture, el, c, canvas } = setup({ stateHistory });
    canvas().selectNode('open');
    canvas().onKey(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
    const stack = canvas().stack();
    fixture.componentRef.setInput('states', [...STATES]);
    fixture.detectChanges();
    expect(canvas().stack()).toBe(stack);

    c.recordId.set('r1');
    c.lookUp(new Event('submit'));
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="smc-totals"]')).toBeTruthy();
    fixture.componentRef.setInput('modelId', 'another');
    fixture.detectChanges();
    expect(c.recordId()).toBe('');
    expect(el.querySelector('[data-testid="smc-totals"]')).toBeNull();
  });

  it('keeps a viewer\'s arrangement for the next time the model opens', () => {
    const { c, canvas } = setup();
    canvas().selectNode('open');
    canvas().onKey(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
    const moved = canvas().stack().doc().nodes[1].ports.y;
    const stored = JSON.parse(localStorage.getItem(`attome.stateModelLayout.${c.modelId()}`) ?? '{}') as Record<string, { y: number }>;
    expect(stored['open'].y).toBe(moved);
  });

  it('shows the server\'s message when the history cannot be read', () => {
    const stateHistory = vi.fn(() => throwError(() => ({ message: 'no access' })));
    const { fixture, el } = setup({ stateHistory });
    const box = el.querySelector('[data-testid="smc-record"]') as HTMLInputElement;
    box.value = 'r1';
    box.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (el.querySelector('[data-testid="smc-lookup"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('[role="alert"]')?.textContent).toContain('no access');
  });
});
