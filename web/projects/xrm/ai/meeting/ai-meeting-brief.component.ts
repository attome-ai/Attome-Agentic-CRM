import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

import { AiMeetingService, MeetingBrief } from './ai-meeting.service';

/** The text direction of a brief or notes written in `language`. */
export function textDir(language: string | null | undefined): 'rtl' | 'ltr' {
  return language === 'ar' ? 'rtl' : 'ltr';
}

/**
 * AI6-T7: a meeting's brief (`GET /api/v1/ai/meetings/{id}/brief`), when it
 * was made, and a button to make it again. The brief runs in its own
 * language's direction; the panel follows the page's.
 */
@Component({
  selector: 'xrm-ai-meeting-brief',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  template: `
    <section class="amb">
      <header class="amb-head">
        <h3>{{ 'aiMeeting.brief.title' | translate }}</h3>
        <button type="button" (click)="regenerate()" [disabled]="busy()">
          {{ (busy() ? 'aiMeeting.brief.working' : 'aiMeeting.brief.regenerate') | translate }}
        </button>
      </header>
      @if (error(); as message) { <p class="amb-error" role="alert">{{ message }}</p> }
      @if (pending(); as reason) { <p class="amb-muted" role="status">{{ 'aiMeeting.brief.pending.' + reason | translate }}</p> }
      @if (brief(); as b) {
        @if (b.status === 'failed') {
          <p class="amb-muted" data-brief-failed>{{ 'aiMeeting.brief.failed' | translate }}</p>
        } @else {
          <div class="amb-text" data-brief-text [attr.dir]="dir(b.language)" [attr.lang]="b.language">{{ b.brief_text }}</div>
        }
        @if (b.generated_at) {
          <small class="amb-muted">{{ 'aiMeeting.brief.generated' | translate }} {{ b.generated_at | localDate }}</small>
        }
      } @else if (!error()) {
        <p class="amb-muted">{{ 'aiMeeting.brief.none' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .amb { display: flex; flex-direction: column; gap: 0.5rem; }
    .amb-head { display: flex; align-items: center; gap: 0.75rem; }
    .amb-head h3 { margin-block: 0; font-size: 1rem; flex: 1 1 auto; }
    .amb-text { white-space: pre-wrap; line-height: 1.5; text-align: start; }
    .amb-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .amb-error { color: var(--color-danger); }
  `],
})
export class AiMeetingBriefComponent implements OnInit {
  private readonly meetings = inject(AiMeetingService);
  private readonly lang = inject(LangService);

  /** The meeting activity's id. */
  readonly meetingId = input.required<string>();

  readonly brief = signal<MeetingBrief | null>(null);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  /** Why a regeneration has not produced a brief yet. */
  readonly pending = signal<'confirmation_required' | 'approval_required' | null>(null);
  readonly dir = textDir;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.meetings.brief(this.meetingId()).subscribe({
      next: brief => { this.brief.set(brief); this.error.set(null); },
      // No brief yet is the normal state before the first one is made.
      error: (e: ApiError) => {
        this.brief.set(null);
        this.error.set(e.status === 404 ? null : this.lang.errorText(e));
      },
    });
  }

  regenerate(): void {
    this.busy.set(true);
    this.pending.set(null);
    this.meetings.regenerateBrief(this.meetingId()).subscribe({
      next: outcome => {
        this.busy.set(false);
        if (outcome.status === 'completed') {
          this.load();
        } else {
          this.pending.set(outcome.status);
        }
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }
}
