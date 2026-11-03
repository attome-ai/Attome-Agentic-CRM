import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import { ON_ERROR_PORT, edgeKey, type GraphDoc, type GraphNodeMark } from '@attome/xrm/canvas';

import { type FlowCoverage, type SimulateResponse } from '../services/workflow-admin.service';

const TONE: Record<string, GraphNodeMark['tone']> = {
  succeeded: 'ran', waiting: 'ran', failed: 'failed', skipped: 'skipped',
};

/**
 * M4-T4 — the marks a simulated run leaves on the graph: what ran, what
 * failed and what the run skipped, each with its status as the note. Pure.
 */
export function simulationMarks(
  result: SimulateResponse | null, note: (status: string) => string,
): Record<string, GraphNodeMark[]> {
  const out: Record<string, GraphNodeMark[]> = {};
  for (const t of result?.trace ?? []) {
    const tone = TONE[t.status];
    if (tone && t.node_id) out[t.node_id] = [{ tone, note: note(t.status) }];
  }
  return out;
}

/**
 * The path the run took: an edge out of a node that ran, through the port it
 * took (a branch names one; a failed node leaves by its error port; any other
 * node by its outputs, not the error port), into a node the run reached. Pure.
 */
export function simulatedPath(result: SimulateResponse | null, doc: GraphDoc): string[] {
  if (!result) return [];
  const byNode = new Map(result.trace.map(t => [t.node_id, t]));
  const reached = (id: string) => {
    const status = byNode.get(id)?.status;
    return status !== undefined && status !== 'skipped';
  };
  return doc.edges.filter(e => {
    const from = byNode.get(e.from_node);
    if (!from || !reached(e.from_node) || !reached(e.to_node)) return false;
    if (from.taken_port) return e.from_port === from.taken_port;
    return from.status === 'failed' ? e.from_port === ON_ERROR_PORT : e.from_port !== ON_ERROR_PORT;
  }).map(edgeKey);
}

/** The shading of the nodes no test case reached. Pure. */
export function coverageMarks(coverage: FlowCoverage | null, note: string): Record<string, GraphNodeMark[]> {
  return Object.fromEntries((coverage?.uncovered ?? []).map(id => [id, [{ tone: 'uncovered' as const, note }]]));
}

/**
 * M4-T4 — a simulated run and the test cases' coverage, beside the canvas that
 * lights the path and shades what is not covered. Selecting a row selects its
 * node.
 */
@Component({
  selector: 'xrm-simulation-view',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="sv" data-testid="simulation-view" [attr.aria-label]="'workflowDesigner.simulation.title' | translate">
      <div class="sv-head">
        <h3>{{ 'workflowDesigner.simulation.title' | translate }}</h3>
        <button type="button" class="sv-close" data-testid="sv-close" (click)="closed.emit()">{{ 'workflowDesigner.simulation.clear' | translate }}</button>
      </div>
      @if (result(); as r) {
        <p role="status" data-testid="sv-status">{{ ('workflowDesigner.simulation.result.' + r.status) | translate }}</p>
        <ol class="sv-trace">
          @for (t of r.trace; track $index) {
            <li data-testid="sv-row" [attr.data-status]="t.status">
              <button type="button" class="sv-node" (click)="pickNode.emit(t.node_id)"><bdi dir="ltr">{{ t.node_id }}</bdi></button>
              <span>{{ ('workflowDesigner.simulation.status.' + t.status) | translate }}</span>
              @if (t.taken_port) { <span class="sv-muted"><bdi dir="ltr">→ {{ t.taken_port }}</bdi></span> }
              @if (t.would_have) { <span class="sv-muted" dir="auto">{{ t.would_have }}</span> }
              @if (t.error) { <span class="sv-error" dir="auto">{{ t.error }}</span> }
            </li>
          }
        </ol>
      }
      @if (coverage(); as c) {
        <h4>{{ 'workflowDesigner.simulation.coverage' | translate }}</h4>
        @if (c.tests.length === 0) {
          <p class="sv-muted" data-testid="sv-no-tests">{{ 'workflowDesigner.simulation.noTests' | translate }}</p>
        } @else {
          <p data-testid="sv-coverage">{{ 'workflowDesigner.simulation.covered' | translate: { covered: c.covered.length, total: c.covered.length + c.uncovered.length } }}</p>
          <ul class="sv-tests">
            @for (t of c.tests; track t.id) {
              <li [class.sv-error]="!t.passed">{{ t.name }}: {{ (t.passed ? 'workflowDesigner.simulation.passed' : 'workflowDesigner.simulation.failed') | translate }}</li>
            }
          </ul>
        }
      }
    </section>
  `,
  styles: [`
    .sv { border: 1px solid var(--color-border, #ddd); border-radius: 8px; padding: .75rem; display: grid; gap: .375rem; font-size: .8125rem; }
    .sv-head { display: flex; align-items: center; gap: .5rem; }
    .sv h3 { margin: 0; font-size: 1rem; }
    .sv h4 { margin: 0; font-size: .8125rem; }
    .sv p { margin: 0; }
    .sv-close { margin-inline-start: auto; }
    .sv-trace, .sv-tests { margin: 0; padding-inline-start: 1.25rem; display: grid; gap: .25rem; }
    .sv-trace li > * { margin-inline-end: .5rem; }
    .sv-node { border: none; background: none; padding: 0; cursor: pointer; color: var(--color-primary, #2b6cb0);
               font-family: ui-monospace, monospace; font-size: .75rem; }
    .sv-muted { color: var(--color-text-secondary, #666); }
    .sv-error { color: var(--color-danger, #c53030); }
  `],
})
export class SimulationViewComponent {
  readonly result = input<SimulateResponse | null>(null);
  readonly coverage = input<FlowCoverage | null>(null);
  readonly closed = output<void>();
  readonly pickNode = output<string>();
}
