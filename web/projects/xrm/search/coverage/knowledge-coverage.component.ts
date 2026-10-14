import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { CollectionCoverage, IndexerStatus, KnowledgeService } from '../services/knowledge.service';

/**
 * Knowledge coverage (chatbot plan C8) — per Knowledge Base collection, what
 * is published, what is chunked, when it was last indexed, and how much is
 * still waiting for a vector, over `GET /api/v1/admin/knowledge/coverage`.
 *
 * A read-only operator view. Every figure is a count of rows that exist, so
 * the screen never infers anything the backend did not count. In particular
 * an absent embedding backlog is said in words — knowledge is lexical-only by
 * configuration — rather than shown as a zero, which would read as "nothing
 * waiting" for a deployment that embeds nothing at all.
 */
@Component({
  selector: 'xrm-knowledge-coverage',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, LocalDatePipe, TranslatePipe],
  templateUrl: './knowledge-coverage.component.html',
  styleUrls: ['../gaps/gap-queue.component.css', './knowledge-coverage.component.css'],
})
export class KnowledgeCoverageComponent implements OnInit {
  private readonly knowledge = inject(KnowledgeService);

  protected readonly collections = signal<CollectionCoverage[]>([]);
  protected readonly total = signal(0);
  /** One-based (D-347). */
  protected readonly page = signal(1);
  protected readonly pageSize = 100;
  protected readonly indexer = signal<IndexerStatus | null>(null);
  protected readonly loading = signal(false);
  /** The read failed (other than a 403); `error` holds the server's message, if any. */
  protected readonly failed = signal(false);
  protected readonly error = signal<string | null>(null);
  /** Set on a 403: the coverage read is admin-only. */
  protected readonly forbidden = signal(false);

  protected readonly totalPages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));

  ngOnInit(): void {
    this.load();
  }

  protected load(): void {
    this.loading.set(true);
    this.failed.set(false);
    this.error.set(null);
    this.forbidden.set(false);
    this.knowledge.indexerStatus().subscribe({
      next: (status) => this.indexer.set(status),
      error: () => this.indexer.set(null),
    });
    this.knowledge.coverage(this.page(), this.pageSize).subscribe({
      next: (reply) => {
        this.collections.set(reply.items);
        this.total.set(reply.total);
        this.page.set(reply.page);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.loading.set(false);
        this.collections.set([]);
        if (e?.status === 403) {
          this.forbidden.set(true);
          return;
        }
        this.failed.set(true);
        this.error.set(e?.message ?? null);
      },
    });
  }

  protected previousPage(): void {
    if (this.page() <= 1 || this.loading()) return;
    this.page.update((p) => p - 1);
    this.load();
  }

  protected nextPage(): void {
    if (this.page() >= this.totalPages() || this.loading()) return;
    this.page.update((p) => p + 1);
    this.load();
  }
}
