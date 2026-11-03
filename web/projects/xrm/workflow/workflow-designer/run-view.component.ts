import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { DatePipe, JsonPipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  GraphCanvasComponent, ON_ERROR_PORT, edgeKey, type GraphDoc, type GraphNodeMark,
} from '@attome/xrm/canvas';

import {
  type InstanceDetail, NODE_TYPES, type NodeRunSummary, WorkflowAdminService, nodeTypeSpec,
} from '../services/workflow-admin.service';
import { placedGraph } from './workflow-designer.component';

/** How often a run still going is read again. */
const WATCH_MS = 5000;
const FINISHED = ['completed', 'failed', 'cancelled'];

const TONE: Record<string, GraphNodeMark['tone']> = {
  completed: 'ran', succeeded: 'ran', failed: 'failed', skipped: 'skipped', running: 'active', waiting: 'active',
  ready: 'active', pending: 'active',
};

/** A node run's place in the replay: started first comes first, not yet started last. Pure. */
export function replayOrder(runs: readonly NodeRunSummary[]): NodeRunSummary[] {
  const at = (r: NodeRunSummary) => (r.started_at ? Date.parse(r.started_at) : Number.POSITIVE_INFINITY);
  return [...runs].sort((a, b) => at(a) - at(b) || (a.round ?? 0) - (b.round ?? 0));
}

/**
 * The runs that had happened at a replay step (`null` is now, the whole run):
 * the first `step + 1` in order. Pure.
 */
export function runsAt(runs: readonly NodeRunSummary[], step: number | null): NodeRunSummary[] {
  const ordered = replayOrder(runs);
  return step === null ? ordered : ordered.slice(0, step + 1);
}

/**
 * The mark of each node from its runs: a node run in a loop has one run a
 * round, and its latest says where it stands. Pure.
 */
export function runMarks(runs: readonly NodeRunSummary[], note: (status: string) => string): Record<string, GraphNodeMark[]> {
  const out: Record<string, GraphNodeMark[]> = {};
  for (const r of runs) {
    out[r.node_id] = [{ tone: TONE[r.status] ?? 'active', note: note(r.status) }];
  }
  return out;
}

/**
 * The edges the run has taken: between two nodes it has reached. A node that
 * failed leaves by its error port, any other by its outputs. A branch's port is
 * not in the run record, so an untaken branch is told by its target: it was
 * skipped, or not reached. Pure.
 */
export function runPath(runs: readonly NodeRunSummary[], doc: GraphDoc): string[] {
  const latest = new Map(runs.map(r => [r.node_id, r.status]));
  const reached = (id: string) => {
    const status = latest.get(id);
    return status !== undefined && status !== 'skipped';
  };
  return doc.edges.filter(e => {
    if (!reached(e.from_node) || !reached(e.to_node)) return false;
    return latest.get(e.from_node) === 'failed' ? e.from_port === ON_ERROR_PORT : e.from_port !== ON_ERROR_PORT;
  }).map(edgeKey);
}

/** How long a run of a node took, in milliseconds; `null` when it has not finished. Pure. */
export function runDuration(run: Pick<NodeRunSummary, 'started_at' | 'completed_at'>): number | null {
  return run.started_at && run.completed_at ? Date.parse(run.completed_at) - Date.parse(run.started_at) : null;
}

/**
 * M2-T3 — a run on its flow's graph: each node coloured by its state, read
 * again while the run goes on. Selecting a node shows each of its runs (one a
 * loop round): the time it took, its input and output, and its error. The
 * server masks credentials in these values. Replay steps forward and back
 * through the run record, showing the graph as it stood at each step.
 */
@Component({
  selector: 'attome-workflow-run-view',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe, GraphCanvasComponent, JsonPipe, RouterLink, TranslatePipe],
  template: `
    <section class="rv">
      <header class="rv-head">
        <h2>{{ 'workflowDesigner.run.title' | translate }}</h2>
        @if (instance(); as i) {
          <span class="rv-badge" data-testid="rv-status">{{ statusNote(i.status) }}</span>
          @if (watching()) { <span class="rv-muted" data-testid="rv-watching" role="status">{{ 'workflowDesigner.run.watching' | translate }}</span> }
          <a class="rv-back" [routerLink]="['/xrm/workflow/instances', i.id]">{{ 'workflowDesigner.run.details' | translate }}</a>
        }
      </header>
      @if (loading()) {
        <p class="rv-muted">{{ 'workflowDesigner.loading' | translate }}</p>
      } @else if (error(); as e) {
        <p class="rv-error" role="alert" data-testid="rv-error">{{ e }}</p>
      } @else {
        <div class="rv-replay" role="group" [attr.aria-label]="'workflowDesigner.run.replay' | translate">
          <button type="button" data-testid="rv-back" [disabled]="!canBack()" (click)="back()">{{ 'workflowDesigner.run.back' | translate }}</button>
          <button type="button" data-testid="rv-forward" [disabled]="step() === null" (click)="forward()">{{ 'workflowDesigner.run.forward' | translate }}</button>
          <button type="button" data-testid="rv-live" [disabled]="step() === null" (click)="step.set(null)">{{ 'workflowDesigner.run.now' | translate }}</button>
          <span role="status" data-testid="rv-position">
            @if (step() === null) { {{ 'workflowDesigner.run.whole' | translate: { total: ordered().length } }} }
            @else { {{ 'workflowDesigner.run.position' | translate: { n: (step() ?? 0) + 1, total: ordered().length } }} }
          </span>
        </div>
        <div class="rv-body">
          <xrm-graph-canvas [doc]="graph()" [kinds]="kinds" [readonly]="true" [nodeMarks]="marks()" [litEdges]="path()"
                            (nodeSelected)="selected.set($event)" />
          <aside class="rv-inspect" data-testid="rv-inspect" [attr.aria-label]="'workflowDesigner.run.inspect' | translate">
            @if (selected(); as id) {
              <h3>{{ typeOf(id) }} <bdi class="rv-id" dir="ltr">{{ id }}</bdi></h3>
              @for (r of selectedRuns(); track $index) {
                <div class="rv-run" data-testid="rv-run">
                  <p>
                    <strong data-testid="rv-run-status">{{ statusNote(r.status) }}</strong>
                    @if (r.round) { <span> · {{ 'workflowDesigner.run.round' | translate: { n: r.round } }}</span> }
                    @if (r.attempt_count > 1) { <span> · {{ 'workflowDesigner.run.attempts' | translate: { n: r.attempt_count } }}</span> }
                  </p>
                  @if (r.started_at) { <p class="rv-muted">{{ r.started_at | date: 'medium' : undefined : locale() }}</p> }
                  @if (took(r) !== null) { <p class="rv-muted" data-testid="rv-took">{{ 'workflowDesigner.run.took' | translate: { ms: took(r) } }}</p> }
                  @if (r.last_error) { <p class="rv-error" dir="auto" data-testid="rv-node-error">{{ r.last_error }}</p> }
                  @if (r.payload_ref) {
                    <p class="rv-muted" data-testid="rv-large">{{ 'workflowDesigner.run.large' | translate }}</p>
                  } @else {
                    <h4>{{ 'workflowDesigner.run.input' | translate }}</h4>
                    <pre dir="ltr" data-testid="rv-input">{{ r.input ?? null | json }}</pre>
                    <h4>{{ 'workflowDesigner.run.output' | translate }}</h4>
                    <pre dir="ltr" data-testid="rv-output">{{ r.output ?? null | json }}</pre>
                  }
                </div>
              } @empty {
                <p class="rv-muted" data-testid="rv-not-run">{{ 'workflowDesigner.run.notRun' | translate }}</p>
              }
            } @else {
              <p class="rv-muted">{{ 'workflowDesigner.run.pick' | translate }}</p>
            }
          </aside>
        </div>
      }
    </section>
  `,
  styles: [`
    .rv { display: grid; gap: .75rem; padding: 1rem; }
    .rv-head { display: flex; align-items: baseline; gap: .75rem; flex-wrap: wrap; }
    .rv-head h2 { margin: 0; font-size: 1.25rem; }
    .rv-back { margin-inline-start: auto; }
    .rv-badge { font-size: .75rem; padding-inline: .5rem; border-radius: 999px; background: var(--color-bg-alt, #eef2f7); }
    .rv-replay { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; font-size: .8125rem; }
    .rv-body { display: grid; grid-template-columns: minmax(0, 1fr) minmax(16rem, 22rem); gap: .75rem; align-items: start; }
    @media (max-width: 64rem) { .rv-body { grid-template-columns: minmax(0, 1fr); } }
    .rv-inspect { border: 1px solid var(--color-border, #ddd); border-radius: 8px; padding: .75rem; display: grid; gap: .5rem; font-size: .8125rem; }
    .rv-inspect h3 { margin: 0; font-size: 1rem; }
    .rv-inspect h4 { margin: .25rem 0 0; font-size: .75rem; }
    .rv-inspect p { margin: 0; }
    .rv-inspect pre { margin: 0; padding: .375rem; overflow: auto; max-block-size: 16rem; font-size: .7rem; text-align: start;
                      background: var(--color-bg-alt, #f5f7fa); border-radius: 6px; }
    .rv-run { display: grid; gap: .25rem; border-block-start: 1px solid var(--color-border, #eee); padding-block-start: .5rem; }
    .rv-id { font-family: ui-monospace, monospace; font-size: .75rem; font-weight: 400; color: var(--color-text-secondary, #777); }
    .rv-muted { color: var(--color-text-secondary, #666); margin: 0; font-size: .8125rem; }
    .rv-error { color: var(--color-danger, #c53030); margin: 0; }
  `],
})
export class WorkflowRunViewComponent implements OnInit {
  readonly id = input.required<string>();

  private readonly svc = inject(WorkflowAdminService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly kinds = NODE_TYPES;
  readonly instance = signal<InstanceDetail | null>(null);
  readonly graph = signal<GraphDoc>({ nodes: [], edges: [] });
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly selected = signal<string | null>(null);
  /** The replay step, an index into the run's order; `null` is the run as it stands. */
  readonly step = signal<number | null>(null);

  readonly ordered = computed(() => replayOrder(this.instance()?.node_runs ?? []));
  readonly shown = computed(() => runsAt(this.instance()?.node_runs ?? [], this.step()));
  readonly marks = computed(() => runMarks(this.shown(), s => this.statusNote(s)));
  readonly path = computed(() => runPath(this.shown(), this.graph()));
  readonly selectedRuns = computed(() => this.shown().filter(r => r.node_id === this.selected()));
  readonly watching = computed(() => {
    const status = this.instance()?.status;
    return !!status && !FINISHED.includes(status);
  });
  readonly canBack = computed(() => this.ordered().length > 0 && this.step() !== 0);
  readonly locale = computed(() => this.lang.intlLocale?.());

  private timer: ReturnType<typeof setTimeout> | null = null;

  ngOnInit(): void {
    this.destroyRef.onDestroy(() => { if (this.timer) clearTimeout(this.timer); });
    this.read(true);
  }

  private later(): void {
    this.timer = setTimeout(() => this.read(false), WATCH_MS);
  }

  private read(first: boolean): void {
    // Tied to the page: an answer after it closes starts no further read.
    this.svc.getInstance(this.id()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: i => {
        this.instance.set(i);
        if (first) this.loadGraph(i);
        if (this.watching()) this.later();
      },
      error: (e: ApiError) => {
        // A failed re-read leaves the last answer on screen; the next one may work.
        if (first) { this.error.set(e.message); this.loading.set(false); }
        else if (this.watching()) this.later();
      },
    });
  }

  private loadGraph(i: InstanceDetail): void {
    this.svc.getVersion(i.definition_id, i.definition_version_id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: v => { this.graph.set(placedGraph(v.graph)); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  statusNote(status: string): string {
    const key = `workflowDesigner.run.status.${status}`;
    const text = this.lang.translate(key);
    return text === key ? status : text;
  }

  back(): void {
    const last = this.ordered().length - 1;
    if (last < 0) return;
    const at = this.step();
    this.go(at === null ? Math.max(0, last - 1) : Math.max(0, at - 1));
  }

  forward(): void {
    const at = this.step();
    if (at === null) return;
    const next = at + 1;
    // Past the last step is the run as it stands.
    if (next >= this.ordered().length - 1) this.step.set(null);
    else this.go(next);
  }

  /** Goes to a step, showing the node it ran. */
  private go(step: number): void {
    this.step.set(step);
    this.selected.set(this.ordered()[step]?.node_id ?? null);
  }

  typeOf(id: string): string {
    const type = this.graph().nodes.find(n => n.id === id)?.type ?? '';
    const key = `workflowNodeType.${type}`;
    const label = this.lang.translate(key);
    return label === key ? (nodeTypeSpec(type)?.label ?? type) : label;
  }

  took(run: NodeRunSummary): number | null {
    return runDuration(run);
  }
}
