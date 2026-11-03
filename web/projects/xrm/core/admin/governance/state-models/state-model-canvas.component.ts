import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal, untracked,
} from '@angular/core';
import { Subscription } from 'rxjs';
import { DatePipe } from '@angular/common';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  GraphCanvasComponent, type GraphDoc, type GraphDocEdge, type GraphNodeKind, type GraphNodeMark,
} from '@attome/xrm/canvas';
import { StateModelsService, type StateHistoryChange, type StateTransition } from '@attome/xrm/core/admin/data';

const IN = 'in';
const OUT = 'out';
const COLUMN = 280;
const ROW = 120;

/** Each state is a node kind of its own: its name, one way in, one way out. Pure. */
export function stateKinds(states: readonly string[]): GraphNodeKind[] {
  return states.map(state => ({
    type: state, label: state, noErrorPort: true,
    inputs: [{ name: IN, portType: 'any' }],
    outputs: [{ name: OUT, portType: 'any' }],
  }));
}

/** Where each state starts: by its distance from the initial state, each distance a column. Pure. */
export function layoutStates(
  states: readonly string[], transitions: readonly Pick<StateTransition, 'from_state' | 'to_state'>[], initial: string,
): Map<string, { x: number; y: number }> {
  const depth = new Map<string, number>();
  const queue = states.includes(initial) ? [initial] : [];
  if (queue.length) depth.set(initial, 0);
  while (queue.length) {
    const at = queue.shift() as string;
    for (const t of transitions) {
      if (t.from_state === at && !depth.has(t.to_state)) {
        depth.set(t.to_state, (depth.get(at) ?? 0) + 1);
        queue.push(t.to_state);
      }
    }
  }
  const lastColumn = Math.max(0, ...depth.values());
  const rows = new Map<number, number>();
  const out = new Map<string, { x: number; y: number }>();
  for (const state of states) {
    // A state nothing leads to yet waits in a column after the rest.
    const column = depth.get(state) ?? lastColumn + 1;
    const row = rows.get(column) ?? 0;
    rows.set(column, row + 1);
    out.set(state, { x: 40 + column * COLUMN, y: 40 + row * ROW });
  }
  return out;
}

/** The model as a graph: states as nodes, transitions as edges. Pure. */
export function stateGraph(
  states: readonly string[],
  transitions: readonly Pick<StateTransition, 'from_state' | 'to_state'>[],
  initial: string,
  placed: ReadonlyMap<string, { x: number; y: number }> = new Map(),
): GraphDoc {
  // A transition may still name a state the field no longer offers: it stays drawn.
  const all = [...new Set([...states, ...transitions.flatMap(t => [t.from_state, t.to_state])])];
  const layout = layoutStates(all, transitions, initial);
  return {
    nodes: all.map(state => ({
      id: state, type: state, config: {},
      ports: placed.get(state) ?? layout.get(state) ?? { x: 40, y: 40 },
    })),
    edges: transitions.map(t => ({ from_node: t.from_state, from_port: OUT, to_node: t.to_state, to_port: IN })),
  };
}

export interface TransitionChanges {
  add: { from: string; to: string }[];
  remove: StateTransition[];
}

/** What a changed graph asks of the saved transitions. A move asks nothing. Pure. */
export function transitionChanges(edges: readonly GraphDocEdge[], saved: readonly StateTransition[]): TransitionChanges {
  const pair = (from: string, to: string) => `${from}\u0000${to}`;
  const drawn = new Set(edges.map(e => pair(e.from_node, e.to_node)));
  const have = new Set(saved.map(t => pair(t.from_state, t.to_state)));
  return {
    add: edges.filter(e => !have.has(pair(e.from_node, e.to_node))).map(e => ({ from: e.from_node, to: e.to_node })),
    remove: saved.filter(t => !drawn.has(pair(t.from_state, t.to_state))),
  };
}

/** One stretch a record spent in a state; `to` is `null` while it is still there. */
export interface StateStay { state: string; from: string; to: string | null; ms: number }

/**
 * A record's stays from its history of the state field, oldest first. The
 * first change's old value is left out: when that state began is not in the
 * field's history. A masked change withholds its value, so it ends a stay and
 * starts none. Pure.
 */
export function stateStays(changes: readonly StateHistoryChange[], field: string, now: number): StateStay[] {
  const moves = changes
    .flatMap(c => c.fields.filter(f => f.field_name === field).map(f => ({ at: c.changed_on, state: f.masked ? null : f.new_value ?? null })))
    .sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  return moves.flatMap((m, i) => {
    if (m.state === null) return [];
    const to = moves[i + 1]?.at ?? null;
    return [{ state: m.state, from: m.at, to, ms: (to ? Date.parse(to) : now) - Date.parse(m.at) }];
  });
}

/** Total time per state, longest first. Pure. */
export function timeInState(stays: readonly StateStay[]): { state: string; ms: number }[] {
  const total = new Map<string, number>();
  for (const s of stays) total.set(s.state, (total.get(s.state) ?? 0) + s.ms);
  return [...total].map(([state, ms]) => ({ state, ms })).sort((a, b) => b.ms - a.ms);
}

/** A duration as whole days, hours and minutes. Pure. */
export function durationParts(ms: number): { days: number; hours: number; minutes: number } {
  const minutes = Math.floor(Math.max(0, ms) / 60_000);
  return { days: Math.floor(minutes / 1440), hours: Math.floor((minutes % 1440) / 60), minutes: minutes % 60 };
}

const layoutKey = (id: string) => `attome.stateModelLayout.${id}`;

/** A viewer's own arrangement of a model's states; the model has no place for one. */
function readLayout(id: string): Map<string, { x: number; y: number }> {
  try {
    const saved: unknown = JSON.parse(localStorage.getItem(layoutKey(id)) ?? '{}');
    return new Map(Object.entries(saved as Record<string, { x: number; y: number }>)
      .filter(([, p]) => typeof p?.x === 'number' && typeof p?.y === 'number'));
  } catch {
    return new Map();
  }
}

function writeLayout(id: string, placed: ReadonlyMap<string, { x: number; y: number }>): void {
  try {
    localStorage.setItem(layoutKey(id), JSON.stringify(Object.fromEntries(placed)));
  } catch {
    // A convenience only: without storage the states open where the layout puts them.
  }
}

/**
 * M8-T4 — a state model on the canvas: the states (the options of the model's
 * Choice field) as nodes, the transitions as edges. Draw a connection to add a
 * transition, delete a wire to remove one; each goes to the server at once
 * through the screen around it, which owns the confirmation and the errors. A
 * record may go back to a state, so loops are allowed. Below it, a record's
 * history of the state field gives its stays and its time in each state.
 */
@Component({
  selector: 'attome-state-model-canvas',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe, GraphCanvasComponent, TranslatePipe],
  template: `
    <section class="smc" data-testid="state-model-canvas">
      <h4>{{ 'governance.stateModels.canvas.title' | translate }}</h4>
      <p class="hint">{{ 'governance.stateModels.canvas.hint' | translate }}</p>
      <xrm-graph-canvas [doc]="doc()" [kinds]="kinds()" [nodeMarks]="marks()" [readonly]="readonly()"
                        [allowCycles]="true" [edgesOnly]="true" (changed)="onChanged($event)" />

      <h4>{{ 'governance.stateModels.history.title' | translate }}</h4>
      <form class="smc-lookup" (submit)="lookUp($event)">
        <label for="smc-record">{{ 'governance.stateModels.history.record' | translate }}</label>
        <input id="smc-record" data-testid="smc-record" dir="ltr" [value]="recordId()" (input)="recordId.set(valueOf($event))" />
        <button type="submit" class="btn-sm" data-testid="smc-lookup" [disabled]="!recordId().trim() || loading()">
          {{ 'governance.stateModels.history.show' | translate }}
        </button>
      </form>
      @if (historyError(); as e) { <p class="error-msg" role="alert">{{ e }}</p> }
      @if (stays(); as list) {
        @if (list.length === 0) {
          <p class="hint" data-testid="smc-no-history">{{ 'governance.stateModels.history.none' | translate }}</p>
        } @else {
          <ul class="smc-totals" data-testid="smc-totals">
            @for (t of totals(); track t.state) {
              <li><strong>{{ t.state }}</strong>: {{ duration(t.ms) }}</li>
            }
          </ul>
          <div class="table-wrap">
            <table data-testid="smc-stays">
              <thead>
                <tr>
                  <th scope="col">{{ 'governance.stateModels.history.state' | translate }}</th>
                  <th scope="col">{{ 'governance.stateModels.history.entered' | translate }}</th>
                  <th scope="col">{{ 'governance.stateModels.history.left' | translate }}</th>
                  <th scope="col">{{ 'governance.stateModels.history.time' | translate }}</th>
                </tr>
              </thead>
              <tbody>
                @for (s of list; track s.from) {
                  <tr>
                    <td class="cell-mono">{{ s.state }}</td>
                    <td>{{ s.from | date: 'medium' : undefined : locale() }}</td>
                    <td>
                      @if (s.to) { {{ s.to | date: 'medium' : undefined : locale() }} }
                      @else { {{ 'governance.stateModels.history.current' | translate }} }
                    </td>
                    <td>{{ duration(s.ms) }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
          @if (truncated()) { <p class="hint" data-testid="smc-truncated">{{ 'governance.stateModels.history.truncated' | translate }}</p> }
        }
      }
    </section>
  `,
  styles: [`
    .smc { display: grid; gap: .5rem; margin-block-end: 20px; }
    .smc h4 { margin: 0; }
    .smc-lookup { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
    .smc-lookup input { min-inline-size: 20rem; max-inline-size: 100%; }
    .smc-totals { margin: 0; padding-inline-start: 1.25rem; }
  `],
})
export class StateModelCanvasComponent {
  readonly modelId = input.required<string>();
  readonly entity = input.required<string>();
  readonly field = input.required<string>();
  readonly states = input.required<readonly string[]>();
  readonly transitions = input.required<readonly StateTransition[]>();
  readonly initial = input.required<string>();
  /** Set while the screen is saving: the graph stays still until the answer. */
  readonly readonly = input(false);

  /** A connection was drawn between two states. */
  readonly addTransition = output<{ from: string; to: string }>();
  /** A wire was deleted. The screen confirms it. */
  readonly removeTransition = output<StateTransition>();

  private readonly svc = inject(StateModelsService);
  private readonly lang = inject(LangService);

  readonly recordId = signal('');
  readonly loading = signal(false);
  readonly historyError = signal<string | null>(null);
  readonly stays = signal<StateStay[] | null>(null);
  readonly truncated = signal(false);
  readonly locale = computed(() => this.lang.intlLocale?.());
  readonly totals = computed(() => timeInState(this.stays() ?? []));

  /** The same states are the same list, so typing elsewhere on the screen leaves the canvas alone. */
  private readonly stateList = computed(() => this.states(), {
    equal: (a, b) => a.length === b.length && a.every((s, i) => s === b[i]),
  });

  private lookup: Subscription | null = null;

  constructor() {
    // Another model is another record's history: nothing carries over.
    effect(() => {
      this.modelId();
      untracked(() => {
        this.lookup?.unsubscribe();
        this.recordId.set('');
        this.stays.set(null);
        this.truncated.set(false);
        this.historyError.set(null);
        this.loading.set(false);
      });
    });
  }

  private placedFor = '';
  private placed = new Map<string, { x: number; y: number }>();

  /** Rebuilt from the saved transitions, so a refused change goes back on the canvas. */
  readonly doc = computed(() => {
    const id = this.modelId();
    if (id !== this.placedFor) {
      this.placedFor = id;
      this.placed = readLayout(id);
    }
    return stateGraph(this.stateList(), this.transitions(), this.initial(), this.placed);
  });
  readonly kinds = computed(() => stateKinds(this.doc().nodes.map(n => n.id)));
  readonly marks = computed<Record<string, GraphNodeMark[]>>(() => ({
    [this.initial()]: [{ tone: 'initial', note: this.lang.translate('governance.stateModels.canvas.initial') }],
  }));

  onChanged(doc: GraphDoc): void {
    const moved = new Map(doc.nodes.map(n => [n.id, { x: n.ports.x, y: n.ports.y }]));
    if ([...moved].some(([id, p]) => {
      const was = this.placed.get(id);
      return !was || was.x !== p.x || was.y !== p.y;
    })) {
      this.placed = moved;
      writeLayout(this.modelId(), moved);
    }
    const asks = transitionChanges(doc.edges, this.transitions());
    asks.add.forEach(a => this.addTransition.emit(a));
    asks.remove.forEach(t => this.removeTransition.emit(t));
  }

  lookUp(event: Event): void {
    event.preventDefault();
    const id = this.recordId().trim();
    if (!id) return;
    this.loading.set(true);
    this.historyError.set(null);
    this.stays.set(null);
    this.lookup?.unsubscribe();
    this.lookup = this.svc.stateHistory(this.entity(), id, this.field()).subscribe({
      next: page => {
        this.stays.set(stateStays(page.items, this.field(), Date.now()));
        this.truncated.set(!!page.next_cursor);
        this.loading.set(false);
      },
      error: (e: ApiError) => { this.historyError.set(e.message); this.loading.set(false); },
    });
  }

  duration(ms: number): string {
    return this.lang.translate('governance.stateModels.history.duration', durationParts(ms));
  }

  protected valueOf(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }
}
