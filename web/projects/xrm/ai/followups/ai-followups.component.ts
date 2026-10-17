import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';
import { logicalToUrlPath } from '@attome/xrm/core/entity';

/** `attome_ai::followup_routes::AiFollowupItem`. */
export interface AiFollowupItem {
  id: string;
  rule_id: string;
  entity: string;
  record_id: string;
  reason: 'stalled_deal' | 'overdue_task' | 'unanswered_customer' | string;
  status: string;
  window_start: string;
  created_at: string;
  row_version: number;
}

/** Whole days since `createdAt`, never below zero. */
export function ageInDays(createdAt: string, now: Date = new Date()): number {
  const days = Math.floor((now.getTime() - new Date(createdAt).getTime()) / 86_400_000);
  return Math.max(0, days);
}

/**
 * My follow-ups (roadmap AI4-T7): the stalled deals, overdue tasks and
 * unanswered customers the follow-up scan found on records I own, with a
 * link to each record and a dismiss button (sent with the item's
 * `row_version`, so a follow-up handled meanwhile is not dismissed twice).
 * Logical CSS only, so it mirrors in Arabic.
 */
@Component({
  selector: 'xrm-ai-followups',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  template: `
    <section class="afu">
      <h2>{{ 'aiFollowups.title' | translate }}</h2>
      <p class="afu-muted">{{ 'aiFollowups.intro' | translate }}</p>
      @if (error(); as message) { <p class="afu-error" role="alert">{{ message }}</p> }
      <ul class="afu-list">
        @for (item of items(); track item.id) {
          <li [attr.data-item]="item.id">
            <span class="afu-reason">{{ 'aiFollowups.reason.' + item.reason | translate }}</span>
            <a [routerLink]="recordPath(item)" [queryParams]="{ id: item.record_id }">{{ 'aiFollowups.open' | translate }}</a>
            <small>{{ 'aiFollowups.age' | translate: { days: age(item.created_at) } }}</small>
            <small>{{ 'aiFollowups.status.' + item.status | translate }}</small>
            <button type="button" (click)="dismiss(item)" [disabled]="busy()">{{ 'aiFollowups.dismiss' | translate }}</button>
          </li>
        } @empty {
          <li class="afu-muted">{{ 'aiFollowups.none' | translate }}</li>
        }
      </ul>
    </section>
  `,
  styles: [`
    :host { display: block; padding-block: 1rem; padding-inline: 1rem; }
    .afu { display: flex; flex-direction: column; gap: 0.75rem; max-inline-size: 60rem; }
    .afu h2 { margin-block: 0; font-size: 1.125rem; }
    .afu-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.375rem; }
    .afu-list li { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center;
      padding-block: 0.5rem; border-block-end: 1px solid var(--color-border); }
    .afu-reason { font-weight: 600; flex: 1 1 12rem; }
    .afu-list button { margin-inline-start: auto; }
    .afu-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .afu-error { color: var(--color-danger); }
  `],
})
export class AiFollowupsComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly items = signal<AiFollowupItem[]>([]);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly age = (createdAt: string) => ageInDays(createdAt);

  ngOnInit(): void {
    this.load();
  }

  recordPath(item: AiFollowupItem): string {
    return `/${logicalToUrlPath(item.entity)}/form`;
  }

  load(): void {
    this.api.get<{ items: AiFollowupItem[] }>('/api/v1/ai/follow-ups?page=1&page_size=100').subscribe({
      next: page => this.items.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  dismiss(item: AiFollowupItem): void {
    this.busy.set(true);
    this.api.post(`/api/v1/ai/follow-ups/${encodeURIComponent(item.id)}/dismiss`, {},
      { ifMatch: item.row_version }).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
