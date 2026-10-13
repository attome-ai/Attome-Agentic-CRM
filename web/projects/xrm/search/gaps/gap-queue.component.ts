import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { EntityService } from '@attome/xrm/core/entity';
import type { ListFilter } from '@attome/xrm';
import { GapTopic, KnowledgeService } from '../services/knowledge.service';

type GapFilter = GapTopic['status'] | 'all';

/** One published KB item offered by the "Addressed" picker. */
interface KnowledgeItemOption {
  id: string;
  title: string;
}

/**
 * The Knowledge Gap Queue (M37 / D-489).
 *
 * What the assistant could not answer, as topics an author can act on. The
 * point of the screen is that an empty queue is *good news* — it means every
 * question asked so far had an answer — and a full one is a writing list, not an
 * error report. The copy says so, because a blank admin table otherwise reads as
 * a broken page.
 */
@Component({
  selector: 'xrm-gap-queue',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe],
  templateUrl: './gap-queue.component.html',
  styleUrls: ['./gap-queue.component.css'],
})
export class GapQueueComponent implements OnInit {
  private readonly knowledge = inject(KnowledgeService);
  private readonly entities = inject(EntityService);

  protected readonly filters: { id: GapFilter; label: string }[] = [
    { id: 'open', label: 'Open' },
    { id: 'addressed', label: 'Addressed' },
    { id: 'dismissed', label: 'Dismissed' },
    { id: 'all', label: 'All' },
  ];

  protected readonly topics = signal<GapTopic[]>([]);
  protected readonly total = signal(0);
  protected readonly filter = signal<GapFilter>('open');
  protected readonly loading = signal(false);
  /** The id of the row with a triage call in flight, so its buttons disable. */
  protected readonly busy = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);

  // ── The "Addressed" picker (D-489) ──────────────────────────────────────
  //
  // Marking a gap addressed with no `addressed_item_ref` records that the
  // question was answered but throws away which article answered it — the
  // one piece of data this queue exists to capture. So "Addressed" opens
  // this picker instead of triaging immediately; only `confirmAddressed`
  // actually calls the API.
  protected readonly pickerFor = signal<GapTopic | null>(null);
  protected readonly pickerQuery = signal('');
  protected readonly pickerResults = signal<KnowledgeItemOption[]>([]);
  protected readonly pickerLoading = signal(false);
  protected readonly pickerSelected = signal<KnowledgeItemOption | null>(null);
  private pickerDebounce?: ReturnType<typeof setTimeout>;

  /** The published Knowledge Base article entity (D-489) the picker searches. */
  private static readonly KNOWLEDGE_ITEM_ENTITY = 'knowledge_data_item';

  ngOnInit(): void {
    this.load();
  }

  protected setFilter(status: GapFilter): void {
    this.filter.set(status);
    this.load();
  }

  protected load(): void {
    this.loading.set(true);
    this.error.set(null);
    const status = this.filter();
    this.knowledge.listGaps({ status: status === 'all' ? undefined : status, pageSize: 100 }).subscribe({
      next: (page) => {
        this.topics.set(page.items);
        this.total.set(page.total);
        this.loading.set(false);
      },
      error: (err: { message?: string }) => {
        this.error.set(err?.message ?? 'Could not load the gap queue.');
        this.loading.set(false);
      },
    });
  }

  /** `dismissed` / `open` need no article reference — triage immediately. */
  protected triage(topic: GapTopic, status: GapTopic['status']): void {
    this.runTriage(topic, status, null);
  }

  /** `addressed` opens the picker instead of triaging directly. */
  protected openAddressedPicker(topic: GapTopic): void {
    this.pickerFor.set(topic);
    this.pickerQuery.set('');
    this.pickerResults.set([]);
    this.pickerSelected.set(null);
    this.searchPicker('');
  }

  protected cancelAddressedPicker(): void {
    clearTimeout(this.pickerDebounce);
    this.pickerFor.set(null);
  }

  protected searchPicker(query: string): void {
    this.pickerQuery.set(query);
    clearTimeout(this.pickerDebounce);
    this.pickerDebounce = setTimeout(() => this.loadPickerResults(query), 200);
  }

  protected selectPickerItem(item: KnowledgeItemOption): void {
    this.pickerSelected.set(item);
  }

  protected confirmAddressedPicker(): void {
    const topic = this.pickerFor();
    const selected = this.pickerSelected();
    if (!topic || !selected) return;
    this.runTriage(topic, 'addressed', selected.id);
    this.pickerFor.set(null);
  }

  private loadPickerResults(query: string): void {
    this.pickerLoading.set(true);
    const filters: ListFilter[] = [{ field: 'lifecycle', op: 'eq', value: 'published' }];
    if (query.trim()) {
      filters.push({ field: 'title', op: 'contains', value: query.trim() });
    }
    this.entities
      .list(GapQueueComponent.KNOWLEDGE_ITEM_ENTITY, {
        filters,
        limit: 20,
        sorts: [{ field: 'title', dir: 'asc' }],
      })
      .subscribe({
        next: (page) => {
          this.pickerLoading.set(false);
          this.pickerResults.set(
            page.data.map((r) => ({ id: r.id, title: String(r.data['title'] ?? r.id) })),
          );
        },
        error: () => {
          this.pickerLoading.set(false);
          this.pickerResults.set([]);
        },
      });
  }

  private runTriage(topic: GapTopic, status: GapTopic['status'], addressedItemRef: string | null): void {
    this.busy.set(topic.id);
    this.knowledge.triageGap(topic.id, status, addressedItemRef).subscribe({
      next: () => {
        this.busy.set(null);
        this.load();
      },
      error: (err: { message?: string }) => {
        this.error.set(err?.message ?? 'Could not update the topic.');
        this.busy.set(null);
      },
    });
  }
}
