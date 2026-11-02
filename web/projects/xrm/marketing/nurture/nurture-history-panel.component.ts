import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { LangService, TranslatePipe } from '@attome/base';

import { HandoffPanelComponent } from './handoff-panel.component';
import { NurtureHistory, NurtureService } from './nurture.service';

/**
 * The Nurture tab of a lead's or contact's form (roadmap E9-T11): a pending
 * hand-off to decide at the top ({@link HandoffPanelComponent}), then the
 * person's nurture programmes, the content they have seen and their past
 * hand-offs. A person the reader may not see shows nothing.
 */
@Component({
  selector: 'xrm-nurture-history-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe, HandoffPanelComponent, TranslatePipe],
  template: `
    <section class="nh" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="nh-title" data-testid="nh">
      <h3 id="nh-title">{{ 'nurturePanel.title' | translate }}</h3>
      @if (failed()) {
        <p role="alert">{{ 'nurturePanel.historyFailed' | translate }}</p>
      } @else if (history(); as h) {
        @if (open(); as handoff) {
          <xrm-handoff-panel [handoff]="handoff" (changed)="reload()" />
        }
        <h4>{{ 'nurturePanel.programmes' | translate }}</h4>
        @if (h.states.length === 0) {
          <p class="nh-empty">{{ 'nurturePanel.notNurtured' | translate }}</p>
        } @else {
          <ul class="nh-list" data-testid="nh-states">
            @for (s of h.states; track s.program_id) {
              <li>
                <bdi dir="ltr">{{ s.program_id }}</bdi>
                <span>{{ 'nurturePanel.status.' + s.status | translate }}</span>
                @if (s.paused_reason) {
                  <span class="nh-muted">{{ 'nurturePanel.paused' | translate }}</span>
                }
              </li>
            }
          </ul>
        }
        <h4>{{ 'nurturePanel.contentSeen' | translate }}</h4>
        @if (h.content_seen.length === 0) {
          <p class="nh-empty">{{ 'nurturePanel.nothingSeen' | translate }}</p>
        } @else {
          <ul class="nh-list" data-testid="nh-seen">
            @for (c of h.content_seen; track c.content_kind + c.content_id) {
              <li>
                <span>{{ c.content_kind }}</span>
                <bdi dir="ltr">{{ c.content_id }}</bdi>
                <span dir="ltr" class="nh-muted">{{ c.first_seen_at | date: 'yyyy-MM-dd' }}</span>
              </li>
            }
          </ul>
        }
        <h4>{{ 'nurturePanel.handoffs' | translate }}</h4>
        @if (h.handoffs.length === 0) {
          <p class="nh-empty">{{ 'nurturePanel.noHandoffs' | translate }}</p>
        } @else {
          <ul class="nh-list" data-testid="nh-handoffs">
            @for (x of h.handoffs; track x.id) {
              <li>
                <span dir="ltr" class="nh-muted">{{ x.created_at | date: 'yyyy-MM-dd' }}</span>
                <span>{{ 'nurturePanel.handoffStatus.' + x.status | translate }}</span>
                @if (x.return_reason) {
                  <bdi>{{ x.return_reason }}</bdi>
                }
              </li>
            }
          </ul>
        }
      }
    </section>
  `,
  styles: [`
    .nh { display: grid; gap: .5rem; padding-block: .5rem; }
    .nh-list { list-style: none; margin: 0; padding: 0; display: grid; gap: .25rem; }
    .nh-list li { display: flex; flex-wrap: wrap; gap: .5rem; align-items: baseline; }
    .nh-muted, .nh-empty { color: var(--color-text-secondary); font-size: .875rem; }
  `],
})
export class NurtureHistoryPanelComponent {
  protected readonly lang = inject(LangService);
  private readonly nurture = inject(NurtureService);

  /** The form's entity: `lead` or `contact`. */
  readonly entityName = input<string>('contact');
  /** The person. */
  readonly recordId = input<string | null>(null);

  readonly history = signal<NurtureHistory | null>(null);
  readonly failed = signal(false);
  private readonly reloads = signal(0);

  /** The hand-off still waiting for sales, if any. */
  readonly open = computed(() =>
    this.history()?.handoffs.find(h => h.status === 'pending' || h.status === 'overdue') ?? null);

  constructor() {
    effect(() => {
      const person = this.recordId();
      const entity = this.entityName();
      this.reloads();
      if (!person) return;
      this.failed.set(false);
      this.nurture.history(person, entity).subscribe({
        next: h => this.history.set(h),
        error: () => { this.history.set(null); this.failed.set(true); },
      });
    });
  }

  reload(): void {
    this.reloads.update(n => n + 1);
  }
}
