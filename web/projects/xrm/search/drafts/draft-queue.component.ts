import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { switchMap } from 'rxjs';
import { LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { EntityService, entityFormRoute } from '@attome/xrm/core/entity';
import type { EntityRecord } from '@attome/xrm';

/** One row of the queue, projected from the entity list page. */
interface DraftRow {
  id: string;
  title: string;
  collection: string | null;
  updatedAt: string;
}

/** What the last action did, announced through the live region. */
type Outcome = { key: string; title: string } | null;

/**
 * The knowledge draft review queue (chatbot plan C8).
 *
 * A draft is an `knowledge_data_item` whose `lifecycle` is `draft`. This
 * screen adds no route and no second write path: it lists drafts through the
 * generic entity list, and its two actions are ordinary entity writes.
 *
 * - **Publish** is `PATCH /api/v1/knowledge_data_item/{id}` with
 *   `lifecycle: published`, under the record's current `row_version`
 *   (`If-Match`). List pages do not reliably carry `row_version`, so the
 *   record is read first. The write emits the change event the search drain's
 *   knowledge arm reindexes (D-489): the article becomes retrievable when the
 *   indexer processes it, not at the moment of the click, and the outcome
 *   message says so.
 * - **Reject** is the entity soft delete, behind an explicit second
 *   confirmation. It is recoverable through the entity's restore, and a
 *   draft never had chunks, so nothing is removed from retrieval.
 *
 * Authorization is the entity's own: a caller without write access on the
 * item gets the server's refusal, shown as-is.
 */
@Component({
  selector: 'xrm-knowledge-draft-queue',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, LocalDatePipe, TranslatePipe],
  templateUrl: './draft-queue.component.html',
  styleUrls: ['../gaps/gap-queue.component.css'],
})
export class DraftQueueComponent implements OnInit {
  private readonly entities = inject(EntityService);

  /** The Knowledge Base article entity (D-489). */
  static readonly ENTITY = 'knowledge_data_item';

  protected readonly formRoute = entityFormRoute(DraftQueueComponent.ENTITY);
  protected readonly drafts = signal<DraftRow[]>([]);
  protected readonly total = signal(0);
  protected readonly loading = signal(false);
  protected readonly failed = signal(false);
  protected readonly error = signal<string | null>(null);
  /** The row with a write in flight, so its buttons disable. */
  protected readonly busy = signal<string | null>(null);
  /** The row whose reject is waiting for its second confirmation. */
  protected readonly rejectConfirm = signal<string | null>(null);
  protected readonly outcome = signal<Outcome>(null);
  /** The last write's server message, when it failed. */
  protected readonly actionError = signal<string | null>(null);

  ngOnInit(): void {
    this.load();
  }

  protected load(): void {
    this.loading.set(true);
    this.failed.set(false);
    this.error.set(null);
    this.entities
      .list(DraftQueueComponent.ENTITY, {
        filters: [{ field: 'lifecycle', op: 'eq', value: 'draft' }],
        limit: 100,
        sorts: [{ field: 'modified_at', dir: 'desc' }],
      })
      .subscribe({
        next: (page) => {
          this.drafts.set(page.data.map((r) => this.toRow(r)));
          this.total.set(page.meta.total);
          this.loading.set(false);
        },
        error: (e: ApiError) => {
          this.loading.set(false);
          this.drafts.set([]);
          this.failed.set(true);
          this.error.set(e?.message ?? null);
        },
      });
  }

  protected publish(row: DraftRow): void {
    if (this.busy()) return;
    this.begin(row);
    this.entities
      .get(DraftQueueComponent.ENTITY, row.id)
      .pipe(
        switchMap((record) =>
          this.entities.update(
            DraftQueueComponent.ENTITY,
            row.id,
            { lifecycle: 'published' },
            record.row_version,
          ),
        ),
      )
      .subscribe({
        next: () => this.done(row, 'knowledgeDrafts.published'),
        error: (e: ApiError) => this.fail(e),
      });
  }

  /** Reject is two-step: this only opens the confirmation for that one row. */
  protected askReject(row: DraftRow): void {
    this.rejectConfirm.set(row.id);
    this.outcome.set(null);
  }

  protected cancelReject(): void {
    this.rejectConfirm.set(null);
  }

  protected confirmReject(row: DraftRow): void {
    if (this.busy()) return;
    this.begin(row);
    this.entities.delete(DraftQueueComponent.ENTITY, row.id).subscribe({
      next: () => this.done(row, 'knowledgeDrafts.rejected'),
      error: (e: ApiError) => this.fail(e),
    });
  }

  private begin(row: DraftRow): void {
    this.busy.set(row.id);
    this.outcome.set(null);
    this.actionError.set(null);
  }

  private done(row: DraftRow, key: string): void {
    this.busy.set(null);
    this.rejectConfirm.set(null);
    this.outcome.set({ key, title: row.title });
    this.load();
  }

  private fail(e: ApiError): void {
    this.busy.set(null);
    this.rejectConfirm.set(null);
    this.outcome.set({ key: 'knowledgeDrafts.actionFailed', title: '' });
    this.actionError.set(e?.message ?? null);
  }

  private toRow(r: EntityRecord): DraftRow {
    const title = r.data['title'];
    return {
      id: r.id,
      title: typeof title === 'string' && title.trim() ? title : r.id,
      collection: r.lookups?.['data_source_ref']?.name ?? null,
      updatedAt: r.updated_at,
    };
  }
}
