import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

import { ServiceHandoff, ServiceHandoffService, canHandBack, partyIcon } from './service-handoff.service';

/**
 * AI7-T6: a ticket's hand-off — the newest one's summary, reasoning, who
 * handed it to whom (an agent, a person or a queue, each with its own icon)
 * and its status — with Accept, and Hand back to agent for a hand-off an
 * agent made: hand back asks for a note (required) and sends the hand-off's
 * `row_version` as If-Match. The summary and reasoning follow their own
 * text's direction; logical CSS only.
 */
@Component({
  selector: 'xrm-service-handoff-card',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  template: `
    @if (handoff(); as h) {
      <section class="shc" [attr.data-handoff]="h.id">
        <header class="shc-head">
          <h3>{{ 'serviceHandoff.title' | translate }}</h3>
          <small class="shc-status">{{ 'serviceHandoff.status.' + h.status | translate }}</small>
        </header>
        <p class="shc-route">
          <span class="shc-party" data-from><i [class]="icon(h.from_kind)" aria-hidden="true"></i> {{ party(h.from_kind, h.from_ref) }}</span>
          <span aria-hidden="true">→</span>
          <span class="shc-party" data-to><i [class]="icon(h.to_kind)" aria-hidden="true"></i> {{ party(h.to_kind, h.to_ref) }}</span>
          <small class="shc-muted">{{ h.created_at | localDate: { dateStyle: 'medium', timeStyle: 'short' } }}</small>
        </p>
        <p class="shc-text" dir="auto"><strong>{{ 'serviceHandoff.summary' | translate }}</strong> {{ h.summary }}</p>
        <p class="shc-text" dir="auto"><strong>{{ 'serviceHandoff.reasoning' | translate }}</strong> {{ h.reasoning }}</p>
        @if (error(); as message) { <p class="shc-error" role="alert">{{ message }}</p> }
        <div class="shc-actions">
          @if (h.status === 'pending') {
            <button type="button" (click)="accept(h)" [disabled]="busy()">{{ 'serviceHandoff.accept' | translate }}</button>
          }
          @if (backable(h) && !backOpen()) {
            <button type="button" (click)="backOpen.set(true)" [disabled]="busy()">{{ 'serviceHandoff.handBack' | translate }}</button>
          }
        </div>
        @if (backOpen()) {
          <form class="shc-back" (ngSubmit)="handBack(h)">
            <label>
              {{ 'serviceHandoff.note' | translate }}
              <textarea name="note" rows="3" [(ngModel)]="note" required dir="auto"></textarea>
            </label>
            @if (noteMissing()) { <p class="shc-error" role="alert" data-note-required>{{ 'serviceHandoff.noteRequired' | translate }}</p> }
            <span class="shc-actions">
              <button type="submit" [disabled]="busy()">{{ 'serviceHandoff.send' | translate }}</button>
              <button type="button" (click)="backOpen.set(false)">{{ 'serviceHandoff.cancel' | translate }}</button>
            </span>
          </form>
        }
      </section>
    }
  `,
  styles: [`
    :host { display: block; }
    .shc { display: flex; flex-direction: column; gap: 0.375rem; padding-block: 0.75rem; padding-inline: 0.75rem;
      border: 1px solid var(--color-border); border-radius: 0.5rem; }
    .shc-head { display: flex; align-items: center; gap: 0.75rem; }
    .shc-head h3 { margin-block: 0; font-size: 1rem; flex: 1 1 auto; }
    .shc-route { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; margin-block: 0; }
    .shc-party { display: inline-flex; gap: 0.25rem; align-items: center; font-weight: 600; }
    .shc-text { margin-block: 0; white-space: pre-wrap; text-align: start; }
    .shc-actions { display: inline-flex; gap: 0.5rem; }
    .shc-back { display: flex; flex-direction: column; gap: 0.375rem; }
    .shc-back label { display: flex; flex-direction: column; gap: 0.25rem; }
    .shc-status, .shc-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .shc-error { color: var(--color-danger); margin-block: 0; }
  `],
})
export class ServiceHandoffCardComponent implements OnInit {
  private readonly handoffs = inject(ServiceHandoffService);
  private readonly lang = inject(LangService);

  /** The ticket's id. */
  readonly ticketId = input.required<string>();

  readonly handoff = signal<ServiceHandoff | null>(null);
  readonly names = signal<Record<string, string>>({});
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly backOpen = signal(false);
  readonly noteMissing = signal(false);
  note = '';
  readonly icon = partyIcon;
  readonly backable = canHandBack;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.handoffs.forTicket(this.ticketId()).subscribe({
      next: page => {
        const latest = page.items[0] ?? null;
        this.handoff.set(latest);
        if (latest) {
          const parties = [
            { kind: latest.from_kind, id: latest.from_ref },
            { kind: latest.to_kind, id: latest.to_ref },
          ];
          for (const p of parties) {
            if (p.kind === 'user') {
              this.handoffs.personName(p.id).subscribe(name => this.names.update(n => ({ ...n, [p.id]: name })));
            }
          }
        }
      },
      // No hand-off service on this deployment: show nothing.
      error: (e: ApiError) => this.error.set(e.status === 404 ? null : this.lang.errorText(e)),
    });
  }

  party(kind: string, id: string): string {
    if (kind === 'agent') return this.lang.translate('serviceHandoff.agent');
    if (kind === 'queue') return this.lang.translate('serviceHandoff.queue');
    return this.names()[id] ?? id;
  }

  accept(h: ServiceHandoff): void {
    this.busy.set(true);
    this.handoffs.accept(h).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }

  handBack(h: ServiceHandoff): void {
    const note = this.note.trim();
    if (!note) {
      this.noteMissing.set(true);
      return;
    }
    this.noteMissing.set(false);
    this.busy.set(true);
    this.handoffs.handBack(h, note).subscribe({
      next: () => { this.busy.set(false); this.backOpen.set(false); this.note = ''; this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }
}
