import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AuthService, LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  AccessReviewCampaign,
  AccessReviewDecision,
  AccessReviewItem,
  AccessReviewsService,
  evidenceCsv,
} from './access-reviews.service';

/**
 * Q11-T1 — access reviews: the campaigns, each campaign's accesses to keep or
 * revoke (all of them, or only those assigned to the signed-in reviewer), a
 * decision with its reason, and the campaign's evidence as CSV (every access,
 * its reviewer, decision, reason and when it was revoked).
 */
@Component({
  selector: 'xrm-access-reviews',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  templateUrl: './access-reviews.component.html',
  styleUrl: './access-reviews.component.css',
})
export class AccessReviewsComponent implements OnInit {
  private readonly reviews = inject(AccessReviewsService);
  private readonly auth = inject(AuthService);

  readonly campaigns = signal<AccessReviewCampaign[]>([]);
  readonly selected = signal<AccessReviewCampaign | null>(null);
  readonly items = signal<AccessReviewItem[]>([]);
  readonly mineOnly = signal(false);
  readonly reasons = signal<Record<string, string>>({});
  readonly busy = signal<string | null>(null);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  /** The items shown: all, or those whose reviewer is the signed-in person. */
  readonly shown = computed(() => {
    const me = this.auth.userId();
    const all = this.items();
    return this.mineOnly() ? all.filter(i => i.reviewer_user_id != null && i.reviewer_user_id === me) : all;
  });

  readonly undecided = computed(() => this.shown().filter(i => !i.decision).length);

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.reviews.listCampaigns().subscribe({
      next: campaigns => {
        this.campaigns.set(campaigns);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.loading.set(false);
      },
    });
  }

  open(campaign: AccessReviewCampaign): void {
    this.selected.set(campaign);
    this.items.set([]);
    this.reasons.set({});
    this.error.set(null);
    this.reviews.listItems(campaign.id).subscribe({
      next: items => this.items.set(items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  close(): void {
    this.selected.set(null);
    this.items.set([]);
  }

  setReason(itemId: string, reason: string): void {
    this.reasons.update(r => ({ ...r, [itemId]: reason }));
  }

  decide(item: AccessReviewItem, decision: AccessReviewDecision): void {
    const campaign = this.selected();
    if (!campaign || item.decision) {
      return;
    }
    this.busy.set(item.id);
    this.error.set(null);
    this.reviews.decide(campaign.id, item.id, decision, this.reasons()[item.id] ?? '').subscribe({
      next: decided => {
        this.items.update(all => all.map(i => (i.id === decided.id ? { ...i, ...decided } : i)));
        this.campaigns.update(all =>
          all.map(c => (c.id === campaign.id ? { ...c, decided_count: c.decided_count + 1 } : c)),
        );
        this.busy.set(null);
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.busy.set(null);
      },
    });
  }

  exportCsv(): void {
    const campaign = this.selected();
    if (!campaign) {
      return;
    }
    const blob = new Blob([evidenceCsv(campaign, this.items())], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `access-review-${campaign.id}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }
}
