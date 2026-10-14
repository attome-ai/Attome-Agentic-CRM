import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { TranslatePipe } from '@attome/base';

/** One bar of a small chart. `share` is 0–100, relative to the largest value. */
export interface AnswerBar {
  label: string;
  value: number;
  share: number;
}

/** A tool result shown as a live component instead of raw JSON (roadmap N1-T3). */
export type AnswerView =
  | {
      kind: 'table';
      columns: { name: string; label: string }[];
      rows: string[][];
      /** A label column and one number column, at most {@link MAX_BARS} rows. */
      bars: AnswerBar[] | null;
    }
  | { kind: 'record'; id: string; fields: { name: string; value: string }[] };

/** Rows a table shows; the full result stays in the raw view. */
export const MAX_TABLE_ROWS = 50;
/** Rows a chart draws. */
export const MAX_BARS = 12;
/** Fields a record card shows. */
export const MAX_CARD_FIELDS = 12;

/** A cell as text: a lookup shows its name, an object its JSON. */
export function cellText(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (typeof value === 'object') {
    const named = value as Record<string, unknown>;
    if (typeof named['name'] === 'string') return named['name'];
    return JSON.stringify(value);
  }
  return String(value);
}

function asObject(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * The live view of a tool result, or `null` to keep the raw text. A query
 * result (`{data: {columns, records}}`) becomes a table, and a chart when it
 * is one label and one number column; a record (`{id, data}`) becomes a card.
 * The content is untrusted model-loop output: it is parsed, never rendered as
 * HTML.
 */
export function answerView(content: string): AnswerView | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }
  const root = asObject(parsed);
  if (!root) return null;

  const data = asObject(root['data']);
  if (data && Array.isArray(data['columns']) && Array.isArray(data['records'])) {
    const columns = (data['columns'] as unknown[])
      .map(asObject)
      .filter((c): c is Record<string, unknown> => !!c && typeof c['name'] === 'string' && c['is_visible'] !== false)
      .map(c => ({ name: String(c['name']), label: String(c['display_name'] ?? c['name']) }));
    if (columns.length === 0) return null;
    const records = (data['records'] as unknown[]).map(asObject).filter((r): r is Record<string, unknown> => !!r);
    const rows = records.slice(0, MAX_TABLE_ROWS).map(r => columns.map(c => cellText(r[c.name])));
    return { kind: 'table', columns, rows, bars: barsFor(columns, records) };
  }

  if (typeof root['id'] === 'string' && data) {
    const fields = Object.entries(data)
      .filter(([, v]) => v !== null && v !== undefined && v !== '')
      .slice(0, MAX_CARD_FIELDS)
      .map(([name, value]) => ({ name, value: cellText(value) }));
    return { kind: 'record', id: root['id'], fields };
  }
  return null;
}

function barsFor(columns: { name: string }[], records: Record<string, unknown>[]): AnswerBar[] | null {
  if (columns.length !== 2 || records.length === 0 || records.length > MAX_BARS) return null;
  const [label, amount] = columns;
  const values = records.map(r => r[amount.name]);
  if (!values.every(v => typeof v === 'number' && Number.isFinite(v) && v >= 0)) return null;
  const max = Math.max(...(values as number[]), 0);
  return records.map((r, i) => {
    const value = values[i] as number;
    return { label: cellText(r[label.name]), value, share: max > 0 ? Math.round((100 * value) / max) : 0 };
  });
}

/**
 * A workflow draft that repeats a conversation's request ("do this every
 * time"): a trigger whose context carries the task, wired into an agent step
 * for the same agent. It is created unpublished; a person reviews, schedules
 * and publishes it in the workflow designer.
 */
export function flowDraft(agentId: string, task: string, now: Date): {
  logicalname: string;
  name: string;
  graph: unknown;
} {
  const stamp = now.toISOString().replace(/[^0-9]/g, '').slice(0, 14);
  const title = task.trim().replace(/\s+/g, ' ').slice(0, 60);
  return {
    logicalname: `assistant_task_${stamp}`,
    name: title || 'Assistant task',
    graph: {
      nodes: [
        { id: 'start', type: 'trigger', config: { kind: 'manual', context: { task: task.trim() } } },
        { id: 'agent', type: 'agent_step', config: { agent_definition_ref: agentId, step_budget: 10 } },
      ],
      edges: [{ from_node: 'start', from_port: 'out', to_node: 'agent', to_port: 'task' }],
    },
  };
}

/** Renders an {@link AnswerView}. Text interpolation only. Logical CSS only. */
@Component({
  selector: 'attome-ai-answer-view',
  standalone: true,
  imports: [TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './copilot-components.html',
  styleUrls: ['./copilot-components.css'],
})
export class AnswerViewComponent {
  readonly view = input.required<AnswerView>();
  readonly table = computed(() => {
    const v = this.view();
    return v.kind === 'table' ? v : null;
  });
  readonly record = computed(() => {
    const v = this.view();
    return v.kind === 'record' ? v : null;
  });
}
