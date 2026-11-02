import { ChangeDetectionStrategy, Component, computed, inject, input, output, signal } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LangService, TranslatePipe } from '@attome/base';

import { Handoff, NurtureService } from './nurture.service';

/** A date (`YYYY-MM-DD`) as an Umm al-Qura date in `locale`, or null. Pure. */
export function hijriDate(date: string, locale: string): string | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return null;
  const at = new Date(`${date}T12:00:00Z`);
  if (Number.isNaN(at.getTime())) return null;
  try {
    return new Intl.DateTimeFormat(`${locale}-u-ca-islamic-umalqura`, { dateStyle: 'long', timeZone: 'UTC' }).format(at);
  } catch {
    return null;
  }
}

/**
 * A pending hand-off to sales on a lead or contact form (roadmap E9-T11):
 * what marketing saw (the score against the hand-off score and the content
 * most recently seen), then accept, or return with a reason and a wake-up
 * date (its Hijri date shown beside it). Only the assignee, their manager or
 * an administrator may decide; the server says so otherwise.
 */
@Component({
  selector: 'xrm-handoff-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DecimalPipe, FormsModule, TranslatePipe],
  template: `
    <section class="hp" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="hp-title" data-testid="hp">
      <h4 id="hp-title">{{ 'nurturePanel.handoffTitle' | translate }}</h4>
      @if (handoff().summary; as s) {
        <p data-testid="hp-score">
          {{ 'nurturePanel.score' | translate }}
          <span dir="ltr">{{ s.score ?? 0 | number: '1.0-1' }} / {{ s.threshold ?? 0 | number: '1.0-1' }}</span>
        </p>
        @if (s.content_seen?.length) {
          <p>{{ 'nurturePanel.seen' | translate }} <span dir="ltr">{{ s.content_seen?.length }}</span></p>
        }
      }
      @if (handoff().due_at) {
        <p>{{ 'nurturePanel.due' | translate }} <span dir="ltr">{{ handoff().due_at }}</span></p>
      }
      @if (decided(); as done) {
        <p data-testid="hp-done">{{ done | translate }}</p>
      } @else {
        <div class="hp-actions">
          <button type="button" class="btn btn-primary" (click)="accept()" [disabled]="busy()"
                  data-testid="hp-accept">{{ 'nurturePanel.accept' | translate }}</button>
        </div>
        <form class="hp-return" (ngSubmit)="giveBack()">
          <label for="hp-reason">{{ 'nurturePanel.reason' | translate }}</label>
          <input id="hp-reason" name="reason" dir="auto" [(ngModel)]="reason" data-testid="hp-reason" />
          <label for="hp-wake">{{ 'nurturePanel.wakeUpOn' | translate }}</label>
          <input id="hp-wake" name="wake" type="date" [ngModel]="wake()" (ngModelChange)="wake.set($event ?? '')"
                 data-testid="hp-wake" />
          @if (wakeHijri(); as h) {
            <span class="hp-hijri" data-testid="hp-hijri">{{ h }}</span>
          }
          <button type="submit" class="btn" [disabled]="busy() || !reason.trim()"
                  data-testid="hp-return">{{ 'nurturePanel.return' | translate }}</button>
        </form>
      }
      @if (error()) {
        <p class="hp-error" role="alert">{{ 'nurturePanel.failed' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .hp { display: grid; gap: .5rem; padding-block: .5rem; border-block-end: 1px solid var(--color-border); }
    .hp p { margin: 0; }
    .hp-actions, .hp-return { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
    .hp-hijri { color: var(--color-text-secondary); font-size: .875rem; }
    .hp-error { color: var(--color-danger); }
  `],
})
export class HandoffPanelComponent {
  protected readonly lang = inject(LangService);
  private readonly nurture = inject(NurtureService);

  readonly handoff = input.required<Handoff>();
  /** Told when the hand-off is accepted or returned. */
  readonly changed = output<void>();

  readonly busy = signal(false);
  readonly error = signal(false);
  /** The catalogue key of what was decided, once it is. */
  readonly decided = signal<string | null>(null);
  protected reason = '';
  /** The wake-up date, `YYYY-MM-DD`, or empty. */
  readonly wake = signal('');

  readonly wakeHijri = computed(() => hijriDate(this.wake(), this.lang.intlLocale()));

  accept(): void {
    this.busy.set(true);
    this.error.set(false);
    this.nurture.accept(this.handoff().id).subscribe({
      next: () => { this.busy.set(false); this.decided.set('nurturePanel.accepted'); this.changed.emit(); },
      error: () => { this.busy.set(false); this.error.set(true); },
    });
  }

  giveBack(): void {
    const reason = this.reason.trim();
    if (!reason) return;
    this.busy.set(true);
    this.error.set(false);
    const wake = this.wake() ? `${this.wake()}T00:00:00Z` : null;
    this.nurture.returnHandoff(this.handoff().id, reason, wake).subscribe({
      next: () => { this.busy.set(false); this.decided.set('nurturePanel.returned'); this.changed.emit(); },
      error: () => { this.busy.set(false); this.error.set(true); },
    });
  }
}
