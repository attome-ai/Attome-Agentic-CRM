import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { logicalToUrlPath } from '@attome/xrm/core/entity';

import { ServiceHandoff, ServiceHandoffService, partyIcon } from './service-handoff.service';

/**
 * AI7-T6: my hand-offs (`service/handoffs`) — the tickets handed to me or
 * to a queue of mine and still waiting, each with who handed it off (an
 * agent or a person), the summary, a link to the ticket and Accept.
 */
@Component({
  selector: 'xrm-service-handoffs-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, RouterLink, TranslatePipe],
  template: `
    <section class="shl">
      <h2>{{ 'serviceHandoff.mine' | translate }}</h2>
      @if (error(); as message) { <p class="shl-error" role="alert">{{ message }}</p> }
      <ul class="shl-list">
        @for (h of items(); track h.id) {
          <li [attr.data-handoff]="h.id">
            <i [class]="icon(h.from_kind)" aria-hidden="true"></i>
            <span class="shl-from">{{ (h.from_kind === 'agent' ? 'serviceHandoff.agent' : 'serviceHandoff.person') | translate }}</span>
            <span class="shl-summary" dir="auto">{{ h.summary }}</span>
            <small class="shl-muted">{{ h.created_at | localDate }}</small>
            <a [routerLink]="ticketPath" [queryParams]="{ id: h.ticket_id }">{{ 'serviceHandoff.openTicket' | translate }}</a>
            <button type="button" (click)="accept(h)" [disabled]="busy()">{{ 'serviceHandoff.accept' | translate }}</button>
          </li>
        } @empty {
          <li class="shl-muted" data-none>{{ 'serviceHandoff.none' | translate }}</li>
        }
      </ul>
    </section>
  `,
  styles: [`
    :host { display: block; padding-block: 1rem; padding-inline: 1rem; }
    .shl { display: flex; flex-direction: column; gap: 0.75rem; max-inline-size: 60rem; }
    .shl h2 { margin-block: 0; font-size: 1.125rem; }
    .shl-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.375rem; }
    .shl-list li { display: flex; flex-wrap: wrap; gap: 0.5rem 0.75rem; align-items: center;
      padding-block: 0.5rem; border-block-end: 1px solid var(--color-border); }
    .shl-from { font-weight: 600; }
    .shl-summary { flex: 1 1 16rem; }
    .shl-list button { margin-inline-start: auto; }
    .shl-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .shl-error { color: var(--color-danger); }
  `],
})
export class ServiceHandoffsListComponent implements OnInit {
  private readonly handoffs = inject(ServiceHandoffService);
  private readonly lang = inject(LangService);

  readonly items = signal<ServiceHandoff[]>([]);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly icon = partyIcon;
  readonly ticketPath = `/${logicalToUrlPath('service_ticket')}/form`;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.handoffs.pending().subscribe({
      next: page => this.items.set(page.items),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  accept(h: ServiceHandoff): void {
    this.busy.set(true);
    this.handoffs.accept(h).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }
}
