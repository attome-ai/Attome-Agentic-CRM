import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { switchMap } from 'rxjs';

/** What ends a contact's sequence. */
export type ExitOn = 'reply' | 'meeting' | 'stage_change';

export const EXITS: readonly ExitOn[] = ['reply', 'meeting', 'stage_change'];

/** A published sequence (`GET /api/v1/workflow/sequences`). */
export interface SequenceSummary {
  logicalname: string;
  name: string;
  published_version: number;
  exit_on: ExitOn[];
  active: number;
}

/** What an enrolment did. */
export interface EnrolOutcome {
  enrolled: number;
  skipped_active: number;
  skipped_missing: number;
}

/** A marketing list to enrol from. */
export interface ListOption {
  id: string;
  name: string;
}

const NAME = /^[a-z0-9_-]{1,100}$/;

/** A logical name from a display name: lower-case words joined by `_`. Pure. */
export function logicalNameOf(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 100);
}

/**
 * The first version of a new sequence: the trigger, then the sending window
 * in the contact's time zone. Steps are added in the workflow editor. Pure.
 */
export function starterGraph(exits: readonly ExitOn[]): Record<string, unknown> {
  return {
    nodes: [
      { id: 'start', type: 'trigger', config: { trigger_type: 'manual' } },
      {
        id: 'window',
        type: 'module_step',
        config: { handler: 'sequence.send_window', config: {} },
      },
    ],
    edges: [{ from_node: 'start', from_port: 'out', to_node: 'window', to_port: 'input' }],
    settings: { sequence: { exit_on: [...exits] } },
  };
}

/**
 * D17-T2: sales sequences. Reps pick a published sequence and enrol a
 * marketing list's contacts in it; an administrator starts a new sequence
 * here (its name and what ends it) and builds its steps in the workflow
 * editor, where it is published.
 */
@Component({
  selector: 'xrm-sequence-builder',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./sequence-builder.component.css'],
  templateUrl: './sequence-builder.component.html',
})
export class SequenceBuilderComponent {
  private readonly api = inject(ApiService);
  private readonly entities = inject(EntityService);
  private readonly router = inject(Router);

  readonly sequences = signal<SequenceSummary[] | null>(null);
  readonly lists = signal<ListOption[]>([]);
  readonly selected = signal<string | null>(null);
  readonly listId = signal<string>('');
  readonly busy = signal(false);
  readonly outcome = signal<EnrolOutcome | null>(null);
  readonly error = signal<string | null>(null);

  // The new-sequence form.
  readonly newName = signal('');
  readonly newExits = signal<ExitOn[]>([...EXITS]);
  readonly creating = signal(false);
  readonly exits = EXITS;

  readonly current = computed(
    () => this.sequences()?.find(s => s.logicalname === this.selected()) ?? null,
  );
  readonly canEnrol = computed(() => !!this.current() && !!this.listId() && !this.busy());
  readonly newLogicalName = computed(() => logicalNameOf(this.newName()));
  readonly canCreate = computed(
    () => NAME.test(this.newLogicalName()) && this.newExits().length > 0 && !this.creating(),
  );

  constructor() {
    this.load();
    this.entities.list('marketing_list', { limit: 100 }).subscribe({
      next: page =>
        this.lists.set(
          page.data.map(r => ({ id: r.id, name: String((r.data as Record<string, unknown>)['name'] ?? r.id) })),
        ),
      // No lists to offer (no marketing package, or no access) is not an error here.
      error: () => this.lists.set([]),
    });
  }

  load(): void {
    this.api
      .get<{ items: SequenceSummary[] }>('/api/v1/workflow/sequences', { page_size: '200' })
      .subscribe({
        next: r => this.sequences.set(r.items ?? []),
        error: (e: ApiError) => {
          this.sequences.set([]);
          this.error.set(e?.message || null);
        },
      });
  }

  select(logicalname: string): void {
    this.selected.set(logicalname);
    this.outcome.set(null);
    this.error.set(null);
  }

  enrol(): void {
    const sequence = this.current();
    const list = this.listId();
    if (!sequence || !list || this.busy()) return;
    this.busy.set(true);
    this.outcome.set(null);
    this.error.set(null);
    this.api
      .post<EnrolOutcome>(
        `/api/v1/workflow/sequences/${encodeURIComponent(sequence.logicalname)}/enrolments`,
        { list_id: list },
      )
      .subscribe({
        next: outcome => {
          this.busy.set(false);
          this.outcome.set(outcome);
          this.load();
        },
        error: (e: ApiError) => {
          this.busy.set(false);
          this.error.set(e?.message || null);
        },
      });
  }

  toggleExit(exit: ExitOn): void {
    const now = this.newExits();
    this.newExits.set(now.includes(exit) ? now.filter(e => e !== exit) : [...now, exit]);
  }

  create(): void {
    if (!this.canCreate()) return;
    this.creating.set(true);
    this.error.set(null);
    this.api
      .post<{ id: string }>('/api/v1/workflow/definitions', {
        logicalname: this.newLogicalName(),
        name: this.newName().trim(),
        kind: 'sequence',
      })
      .pipe(
        switchMap(definition =>
          this.api.post<{ id: string; definition_id: string }>(
            `/api/v1/workflow/definitions/${definition.id}/versions`,
            { graph: starterGraph(this.newExits()) },
          ),
        ),
      )
      .subscribe({
        next: version => {
          this.creating.set(false);
          void this.router.navigate([
            '/xrm/workflow/definitions', version.definition_id, 'versions', version.id,
          ]);
        },
        error: (e: ApiError) => {
          this.creating.set(false);
          this.error.set(e?.message || null);
        },
      });
  }
}
