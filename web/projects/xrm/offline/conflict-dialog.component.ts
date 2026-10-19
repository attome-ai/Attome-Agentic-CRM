import { ChangeDetectionStrategy, Component, computed, inject, input, output, signal } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import { NewOp, OfflineQueueService, QueuedOp } from './offline-queue.service';
import { SyncProblem } from './sync.service';

/** One clashing attribute: the person's value and the server's. */
export interface ConflictRow {
  field: string;
  mine: unknown;
  server: unknown;
}

/** The clashing attributes of a conflict, by name. Pure. */
export function conflictRows(problem: SyncProblem): ConflictRow[] {
  const server = problem.result.server_values ?? {};
  const mine = problem.op.changed ?? {};
  return Object.keys(server)
    .sort()
    .map(field => ({ field, mine: mine[field] ?? null, server: server[field] ?? null }));
}

/**
 * The change that resolves a conflict: everything the person changed, with
 * each clashing attribute set to the side they chose, against the server's
 * current version (so it applies as is). Pure; `null` until every clashing
 * attribute has a choice — the server's value is never picked for them.
 */
export function resolvedOp(problem: SyncProblem, choices: Record<string, 'mine' | 'server'>): NewOp | null {
  const rows = conflictRows(problem);
  if (rows.some(r => !choices[r.field])) return null;
  const changed: Record<string, unknown> = { ...(problem.op.changed ?? {}) };
  const base: Record<string, unknown> = { ...(problem.op.base_values ?? {}) };
  for (const r of rows) {
    changed[r.field] = choices[r.field] === 'mine' ? r.mine : r.server;
    base[r.field] = r.server;
  }
  return {
    kind: 'update',
    entity: problem.op.entity,
    id: problem.op.id,
    base_row_version: problem.result.row_version,
    changed,
    base_values: base,
  };
}

/** A value as text, for showing both sides. */
function shown(v: unknown): string {
  if (v === null || v === undefined) return '';
  return typeof v === 'object' ? JSON.stringify(v) : String(v);
}

/**
 * B18-T9: resolves an offline edit that clashed with someone else's, one
 * attribute at a time. Each clashing attribute shows the person's value
 * ("Mine", at inline-start) and the server's side by side; nothing is chosen
 * for them. Save queues a new update with the chosen values against the
 * server's version, so no text is lost either way.
 */
@Component({
  selector: 'xrm-offline-conflict-dialog',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  templateUrl: './conflict-dialog.component.html',
  styleUrls: ['./conflict-dialog.component.css'],
})
export class ConflictDialogComponent {
  readonly problem = input.required<SyncProblem>();
  readonly resolved = output<QueuedOp>();
  readonly cancelled = output<void>();

  private readonly queue = inject(OfflineQueueService);

  readonly rows = computed(() => conflictRows(this.problem()));
  readonly choices = signal<Record<string, 'mine' | 'server'>>({});
  readonly saving = signal(false);
  readonly ready = computed(() => resolvedOp(this.problem(), this.choices()) !== null);

  readonly shown = shown;

  choose(field: string, side: 'mine' | 'server'): void {
    this.choices.update(c => ({ ...c, [field]: side }));
  }

  chooseAll(side: 'mine' | 'server'): void {
    this.choices.set(Object.fromEntries(this.rows().map(r => [r.field, side])));
  }

  async save(): Promise<void> {
    const op = resolvedOp(this.problem(), this.choices());
    if (!op || this.saving()) return;
    this.saving.set(true);
    try {
      this.resolved.emit(await this.queue.enqueue(op));
    } finally {
      this.saving.set(false);
    }
  }
}
