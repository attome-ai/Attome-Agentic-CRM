import { ChangeDetectionStrategy, Component, effect, inject, input, output, signal, untracked } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import type { ChoiceOptions } from '@attome/xrm';
import { EntityService } from '@attome/xrm/core/entity';
import type { AvailableTransition } from '@attome/xrm/core/entity';
import {
  AvailableView, KanbanViewMetadata, QueryService, ViewAdminService,
} from '@attome/xrm/core/query/data';

/** One kanban card, positioned by its current `state_field` value. */
interface KanbanCard {
  id:     string;
  state:  string;
  fields: { label: string; value: string }[];
}

interface KanbanColumn {
  value:     string;
  /** `null` = no WIP limit configured for this state (D-429: advisory only,
   * never enforced server-side — a column over its limit still accepts a
   * drop, it just renders the count/limit in a warning style). */
  wipLimit:  number | null;
  cards:     KanbanCard[];
}

/**
 * `kind = kanban` (D-429/M64): columns = the state field's choice values,
 * card fields = the view's own `table_definition` columns. Drag-and-drop
 * issues `POST /{entity}/{id}/transition` — **this component never decides
 * whether a transition is legal.** The only source of truth for "which
 * states can this card move to" is `GET /{entity}/{id}/transitions`, fetched
 * fresh when a card starts dragging; a column not named in that response is
 * never an offered drop target, and the transition endpoint enforces the
 * move again regardless (the same `check_transition` a raw `PATCH` runs).
 */
@Component({
  selector:   'xrm-kanban-board',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [TranslatePipe],
  templateUrl: './kanban-board.component.html',
  styleUrl:    './kanban-board.component.css',
})
export class KanbanBoardComponent {
  readonly entityName = input.required<string>();
  /** Which `kind = kanban` view to render — defaults to the entity's first one. */
  readonly viewId = input<string | null>(null);

  readonly cardClick = output<string>();

  private readonly querySvc  = inject(QueryService);
  private readonly viewSvc   = inject(ViewAdminService);
  private readonly entitySvc = inject(EntityService);
  private readonly lang      = inject(LangService);

  readonly loading = signal(false);
  readonly error   = signal<string | null>(null);
  readonly columns = signal<KanbanColumn[]>([]);
  readonly view     = signal<AvailableView | null>(null);

  /** The card currently being dragged, and the set of state values it may
   * legally move to — populated from `listTransitions`, nothing else. */
  private readonly draggingCardId = signal<string | null>(null);
  readonly draggingAllowedStates = signal<Set<string> | null>(null);
  readonly transitionError = signal<string | null>(null);

  constructor() {
    effect(() => {
      this.entityName();
      this.viewId();
      untracked(() => this.load());
    });
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.columns.set([]);
    this.view.set(null);

    this.viewSvc.listAvailable(this.entityName()).subscribe({
      next: views => {
        const requested = this.viewId();
        const target = requested
          ? views.find(v => v.id === requested && v.kind === 'kanban')
          : views.find(v => v.kind === 'kanban');
        if (!target) {
          this.loading.set(false);
          this.error.set(this.lang.translate('entityViews.kanban.noView'));
          return;
        }
        this.view.set(target);
        this.loadBoard(target);
      },
      error: (e: ApiError) => { this.loading.set(false); this.error.set(e.message); },
    });
  }

  private loadBoard(view: AvailableView): void {
    const meta = view.view_metadata as unknown as KanbanViewMetadata;
    const stateField = meta.state_field;
    if (!stateField) {
      this.loading.set(false);
      this.error.set(this.lang.translate('entityViews.kanban.noStateField'));
      return;
    }

    this.entitySvc.getSchema(this.entityName()).subscribe({
      next: schema => {
        const field = schema.fields.find(f => f.name === stateField);
        const choices = field && field.field_type === 'choice'
          ? (field.options as ChoiceOptions).choices
          : [];

        this.querySvc.execute({
          view_id: view.id, page: 1, page_size: 500, include_total: true,
        }).subscribe({
          next: res => {
            const wipLimits = meta.wip_limits ?? {};
            const byState = new Map<string, KanbanCard[]>();
            for (const value of choices) byState.set(value, []);
            for (const record of res.data.records) {
              const state = String(record[stateField] ?? '');
              const card: KanbanCard = {
                id: String(record['id'] ?? ''),
                state,
                fields: res.data.columns
                  .filter(c => c.is_visible && c.name !== stateField)
                  .map(c => ({ label: c.display_name, value: this.formatValue(record[c.name]) })),
              };
              const bucket = byState.get(state);
              if (bucket) { bucket.push(card); } else { byState.set(state, [card]); }
            }
            this.columns.set(
              [...byState.entries()].map(([value, cards]) => ({
                value,
                wipLimit: wipLimits[value] ?? null,
                cards,
              })),
            );
            this.loading.set(false);
          },
          error: (e: ApiError) => { this.loading.set(false); this.error.set(e.message); },
        });
      },
      error: (e: ApiError) => { this.loading.set(false); this.error.set(e.message); },
    });
  }

  private formatValue(value: unknown): string {
    if (value === null || value === undefined) return '';
    if (Array.isArray(value)) return value.join(', ');
    return String(value);
  }

  isOverWip(col: KanbanColumn): boolean {
    return col.wipLimit !== null && col.cards.length > col.wipLimit;
  }

  onCardClick(card: KanbanCard): void { this.cardClick.emit(card.id); }

  // ── Drag and drop — offers only what GET .../transitions returned ────────

  onDragStart(card: KanbanCard, event: DragEvent): void {
    this.transitionError.set(null);
    this.draggingCardId.set(card.id);
    this.draggingAllowedStates.set(null);
    event.dataTransfer?.setData('text/plain', card.id);
    this.entitySvc.listTransitions(this.entityName(), card.id).subscribe({
      next: res => {
        this.draggingAllowedStates.set(
          new Set((res.items as AvailableTransition[]).map(t => t.to_state)),
        );
      },
      // A failed transitions lookup means "offer nothing" — never fall back
      // to assuming every column is a legal target.
      error: () => this.draggingAllowedStates.set(new Set()),
    });
  }

  onDragEnd(): void {
    this.draggingCardId.set(null);
    this.draggingAllowedStates.set(null);
  }

  isDropTarget(col: KanbanColumn): boolean {
    return this.draggingAllowedStates()?.has(col.value) ?? false;
  }

  onDragOver(col: KanbanColumn, event: DragEvent): void {
    if (this.isDropTarget(col)) event.preventDefault();
  }

  onDrop(col: KanbanColumn, event: DragEvent): void {
    event.preventDefault();
    const cardId = this.draggingCardId();
    if (!cardId || !this.isDropTarget(col)) return;
    this.entitySvc.transition(this.entityName(), cardId, { to_state: col.value }).subscribe({
      next: () => {
        const view = this.view();
        if (view) this.loadBoard(view);
      },
      // The API is the enforcement point (D-429) -- a 422/409 here is a
      // normal, expected outcome (state moved concurrently, or a guard this
      // component was never told about), not a client bug.
      error: (e: ApiError) => this.transitionError.set(e.message),
    });
  }

  dismissTransitionError(): void { this.transitionError.set(null); }
}
