import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { logicalToUrlPath } from '@attome/xrm/core/entity';
import { Observable } from 'rxjs';

import {
  BulkOutcome, MyQueuesService, QueueItemRow, QueueRef, STARTER_SETS, StarterSetKey, groupByQueue, missingStarters,
} from './my-queues.service';

/**
 * G4-T3: my queues (`service/queues`) — every open item of the V7 queues in
 * one list, grouped by queue, with bulk pick, release and transfer (G4-T2),
 * and starter queue sets for IT, customer care and HR.
 */
@Component({
  selector: 'xrm-my-queues',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, RouterLink, TranslatePipe],
  templateUrl: './my-queues.component.html',
  styleUrl: './my-queues.component.css',
})
export class MyQueuesComponent implements OnInit {
  private readonly service = inject(MyQueuesService);
  private readonly lang = inject(LangService);

  readonly queues = signal<QueueRef[]>([]);
  readonly items = signal<QueueItemRow[]>([]);
  readonly selected = signal<ReadonlySet<string>>(new Set());
  readonly transferTo = signal('');
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly outcome = signal<BulkOutcome | null>(null);
  readonly groups = computed(() => groupByQueue(this.queues(), this.items()));
  readonly selectedCount = computed(() => this.selected().size);
  readonly starterKeys = Object.keys(STARTER_SETS) as StarterSetKey[];

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.error.set(null);
    this.service.queues().subscribe({
      next: queues => this.queues.set(queues),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
    this.service.openItems().subscribe({
      next: items => {
        this.items.set(items);
        const live = new Set(items.map(i => i.id));
        this.selected.set(new Set([...this.selected()].filter(id => live.has(id))));
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  recordPath(item: QueueItemRow): string {
    return `/${logicalToUrlPath(item.record_entity)}/form`;
  }

  isSelected(id: string): boolean {
    return this.selected().has(id);
  }

  toggle(id: string): void {
    const next = new Set(this.selected());
    if (next.has(id)) next.delete(id); else next.add(id);
    this.selected.set(next);
  }

  toggleGroup(items: readonly QueueItemRow[]): void {
    const next = new Set(this.selected());
    const all = items.every(i => next.has(i.id));
    for (const i of items) {
      if (all) next.delete(i.id); else next.add(i.id);
    }
    this.selected.set(next);
  }

  groupChecked(items: readonly QueueItemRow[]): boolean {
    return items.length > 0 && items.every(i => this.selected().has(i.id));
  }

  pickSelected(): void {
    this.run(id => this.service.pick(id));
  }

  releaseSelected(): void {
    this.run(id => this.service.release(id));
  }

  transferSelected(): void {
    const to = this.transferTo();
    if (!to) return;
    this.run(id => this.service.transfer(id, to));
  }

  onTransferTo(event: Event): void {
    this.transferTo.set((event.target as HTMLSelectElement).value);
  }

  addStarters(key: StarterSetKey): void {
    const starters = missingStarters(key, this.queues());
    this.busy.set(true);
    this.service.createStarters(starters, this.lang.current()).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }

  private run(act: (id: string) => Observable<unknown>): void {
    const ids = [...this.selected()];
    if (!ids.length) return;
    this.busy.set(true);
    this.outcome.set(null);
    this.service.bulk(ids, act).subscribe(outcome => {
      this.busy.set(false);
      this.outcome.set(outcome);
      this.selected.set(new Set());
      this.load();
    });
  }
}
