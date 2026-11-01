import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `attome_service::oncall::pages::OnCallPage`. */
export interface OnCallPage {
  id: string;
  ticket_id: string;
  subject: string;
  paged_at: string;
  acknowledged_at?: string | null;
}

/**
 * H7-T2: the caller's own pages, newest first; an open page has an
 * Acknowledge button. A page link from a notification
 * (`/xrm/service/oncall?page=<id>`) is highlighted. Logical CSS only.
 */
@Component({
  selector: 'xrm-oncall-pages',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  styles: [`
    :host { display: block; }
    .op-list { display: flex; flex-direction: column; gap: 0.5rem; padding-inline-start: 0; list-style: none; }
    .op-item { display: flex; flex-wrap: wrap; gap: 0.25rem 0.75rem; align-items: baseline;
               padding: 0.5rem 0.75rem; border: 1px solid var(--color-border); border-radius: 0.5rem; }
    .op-focus { border-color: var(--color-primary); }
    .op-open { color: var(--color-danger); font-weight: 600; }
    .op-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
  `],
  template: `
    <section [attr.aria-label]="'oncallCalendar.pages.title' | translate">
      <h3>{{ 'oncallCalendar.pages.title' | translate }}</h3>
      @if (error(); as message) { <p class="op-open" role="alert">{{ message }}</p> }
      @if (pages().length === 0) {
        <p class="op-muted">{{ 'oncallCalendar.pages.none' | translate }}</p>
      } @else {
        <ul class="op-list" data-testid="op-list">
          @for (p of pages(); track p.id) {
            <li class="op-item" [class.op-focus]="p.id === focus()">
              <span dir="auto">{{ p.subject }}</span>
              <span class="op-muted">{{ p.paged_at | localDate }}</span>
              @if (p.acknowledged_at) {
                <span class="op-muted">{{ 'oncallCalendar.pages.acknowledged' | translate }}</span>
              } @else {
                <span class="op-open">{{ 'oncallCalendar.pages.open' | translate }}</span>
                <button type="button" [disabled]="busy()" (click)="acknowledge(p)">
                  {{ 'oncallCalendar.pages.acknowledge' | translate }}
                </button>
              }
            </li>
          }
        </ul>
      }
    </section>
  `,
})
export class OncallPagesComponent implements OnInit {
  private readonly api = inject(ApiService);

  /** The page a notification opened, if any. */
  readonly focus = input<string | null>(null);

  readonly pages = signal<OnCallPage[]>([]);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.api.get<{ items: OnCallPage[] }>('/api/v1/service/oncall/pages', { page_size: '20' }).subscribe({
      next: r => this.pages.set(r.items ?? []),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  acknowledge(page: OnCallPage): void {
    this.busy.set(true);
    this.error.set(null);
    this.api.post<OnCallPage>(`/api/v1/service/oncall/pages/${encodeURIComponent(page.id)}/acknowledge`, {}).subscribe({
      next: done => {
        this.busy.set(false);
        this.pages.update(ps => ps.map(p => (p.id === done.id ? done : p)));
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
