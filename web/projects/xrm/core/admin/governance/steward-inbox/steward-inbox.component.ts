import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, SdkService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { GovernanceNavComponent } from '../nav/governance-nav.component';

/** One item of `GET /api/v1/governance/inbox` (L3-T3). */
export interface InboxItem {
  source: string;
  id: string;
  entity: string;
  record_id?: string | null;
  related_id?: string | null;
  detail: string;
  due_at: string;
  link: string;
}

/**
 * L3-T7 — the steward's inbox: open duplicates, quality issues and legal
 * holds in the caller's domains, oldest first, each linking to the screen
 * that handles it. Read only; one column of cards, so it works at 360 px.
 * Logical CSS only.
 */
@Component({
  selector: 'xrm-steward-inbox',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, LocalDatePipe, TranslatePipe, GovernanceNavComponent],
  styleUrls: ['../../../../styles/admin-page.css', '../governance.css'],
  styles: [`
    .si-list { display: flex; flex-direction: column; gap: 0.5rem; padding-inline-start: 0; list-style: none; }
    .si-item { display: flex; flex-wrap: wrap; gap: 0.25rem 0.75rem; align-items: baseline;
               padding: 0.5rem 0.75rem; border: 1px solid var(--color-border); border-radius: 0.5rem; }
    .si-source { font-weight: 600; }
    .si-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .si-detail { flex-basis: 100%; overflow-wrap: anywhere; }
  `],
  template: `
    <xrm-governance-nav />
    <div class="page-header">
      <div>
        <h2>{{ 'governance.inbox.title' | translate }}</h2>
        <p class="subtitle">{{ 'governance.inbox.subtitle' | translate }}</p>
      </div>
    </div>
    @if (error(); as message) { <p class="error-msg" role="alert">{{ message }}</p> }
    @if (items(); as list) {
      @if (list.length === 0) {
        <p class="si-muted" role="status">{{ 'governance.inbox.empty' | translate }}</p>
      } @else {
        <ul class="si-list" data-testid="si-list">
          @for (item of list; track item.source + item.id) {
            <li class="si-item">
              <span class="si-source">{{ ('governance.inbox.sources.' + item.source) | translate }}</span>
              <span class="si-muted" dir="ltr">{{ item.entity }}</span>
              <span class="si-muted">{{ item.due_at | localDate }}</span>
              <span class="si-detail" dir="auto">{{ item.detail }}</span>
              @if (item.link) {
                <a [routerLink]="item.link">{{ 'governance.inbox.open' | translate }}</a>
              }
            </li>
          }
        </ul>
      }
    }
  `,
})
export class StewardInboxComponent implements OnInit {
  private readonly sdk = inject(SdkService);

  readonly items = signal<InboxItem[] | null>(null);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.sdk.getAllPages<InboxItem>('/api/v1/governance/inbox').subscribe({
      next: items => this.items.set(items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
