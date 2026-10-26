import { ChangeDetectionStrategy, Component, Injector, computed, inject, input, output, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

/** One action as `GET /api/v1/actions` lists it for the caller. */
export interface CatalogAction {
  id: string;
  description: string;
  /** `Read` | `Reversible` | `Consequential`. */
  risk: string;
  input_schema?: {
    required?: string[];
    properties?: Record<string, { enum?: unknown[]; const?: unknown }>;
  };
}

/** What an invocation answered (`ActionOutcome`, tagged by `status`). */
export interface ActionAnswer {
  status: string;
  reason?: string;
}

/** The custom-action id prefix (AE1-T1). */
export const CUSTOM_PREFIX = 'custom.';

/**
 * AE1-T5: whether `action` can run from a record (`bulk` false) or a
 * selection (`bulk` true) of `entity` with nothing else to ask. A record
 * action requires `entity` and `record_id`, a bulk one `entity` and
 * `record_ids`, and nothing more; an `enum` or `const` on `entity` limits the
 * entities it shows on.
 */
export function appliesTo(action: CatalogAction, entity: string, bulk: boolean): boolean {
  if (!action.id.startsWith(CUSTOM_PREFIX)) return false;
  const schema = action.input_schema ?? {};
  const required = new Set(schema.required ?? []);
  const target = bulk ? 'record_ids' : 'record_id';
  if (!required.has('entity') || !required.has(target)) return false;
  if (required.size !== 2) return false;
  const entityProp = schema.properties?.['entity'];
  if (entityProp?.const !== undefined && entityProp.const !== entity) return false;
  if (Array.isArray(entityProp?.enum) && !entityProp.enum.includes(entity)) return false;
  return true;
}

/** The label a custom action shows: its name without the prefix. */
export function actionLabel(action: CatalogAction): string {
  return action.id.slice(CUSTOM_PREFIX.length).replace(/[_-]+/g, ' ');
}

type Notice =
  | { kind: 'done' | 'approval' | 'waiting' | 'error'; text?: string }
  | { kind: 'confirm'; action: CatalogAction; text: string };

/**
 * AE1-T5: the custom actions a person can run on a record (the form header)
 * or on the selected records (the list toolbar). The catalogue is read when
 * the menu is first opened, never on render. A consequential action answers
 * `confirmation_required` first (AE1-T4); the person confirms and it runs
 * again with `confirm`. An action that goes to approval says so.
 */
@Component({
  selector: 'xrm-action-bar',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./action-bar.component.css'],
  templateUrl: './action-bar.component.html',
})
export class ActionBarComponent {
  // Resolved when first used, so a host that never opens the menu needs no
  // HTTP client (the form and list specs render this component).
  private readonly injector = inject(Injector);
  private get api(): ApiService {
    return this.injector.get(ApiService);
  }

  /** Logical name of the records' entity. */
  readonly entity = input.required<string>();
  /** The record on a form; leave unset on a list. */
  readonly recordId = input<string | null>(null);
  /** The selected records on a list. */
  readonly recordIds = input<readonly string[]>([]);
  readonly disabled = input(false);
  /** An action ran; the host may reload. */
  readonly ran = output<string>();

  readonly open = signal(false);
  readonly catalog = signal<CatalogAction[] | null>(null);
  readonly busy = signal(false);
  readonly notice = signal<Notice | null>(null);

  readonly bulk = computed(() => !this.recordId());
  readonly available = computed(() =>
    (this.catalog() ?? []).filter(a => appliesTo(a, this.entity(), this.bulk())),
  );
  readonly label = actionLabel;

  toggle(): void {
    if (this.open()) {
      this.open.set(false);
      return;
    }
    this.open.set(true);
    if (this.catalog() !== null) return;
    this.api.get<{ items: CatalogAction[] }>('/api/v1/actions').subscribe({
      next: r => this.catalog.set(r.items ?? []),
      error: () => this.catalog.set([]),
    });
  }

  run(action: CatalogAction, confirm = false): void {
    if (this.busy() || this.disabled()) return;
    const entity = this.entity();
    const record = this.recordId();
    const records = this.recordIds();
    if (!record && records.length === 0) return;
    this.busy.set(true);
    this.notice.set(null);
    const call = record
      ? this.api.post<ActionAnswer>(
          `/api/v1/${encodeURIComponent(entity)}/${encodeURIComponent(record)}/actions/${encodeURIComponent(action.id)}`,
          { args: {}, confirm },
        )
      : this.api.post<ActionAnswer>(`/api/v1/actions/${encodeURIComponent(action.id)}/invoke`, {
          args: { entity, record_ids: [...records] },
          confirm,
        });
    call.subscribe({
      next: answer => {
        this.busy.set(false);
        this.answer(action, answer);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.notice.set({ kind: 'error', text: e?.message || undefined });
      },
    });
  }

  confirm(): void {
    const notice = this.notice();
    if (notice?.kind === 'confirm') this.run(notice.action, true);
  }

  dismiss(): void {
    this.notice.set(null);
  }

  private answer(action: CatalogAction, answer: ActionAnswer): void {
    switch (answer.status) {
      case 'completed':
        this.open.set(false);
        this.notice.set({ kind: 'done' });
        this.ran.emit(action.id);
        return;
      case 'confirmation_required':
        this.notice.set({ kind: 'confirm', action, text: answer.reason ?? '' });
        return;
      case 'approval_required':
        this.open.set(false);
        this.notice.set({ kind: 'approval' });
        return;
      default:
        this.open.set(false);
        this.notice.set({ kind: 'waiting' });
    }
  }
}
