import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

import { AiWorkShareService, DoneBy, ProcessShare, ShareDay, ShareEvent } from './ai-work-share.service';

/** `YYYY-MM-DD` of a date (UTC). Pure. */
function isoDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

/** The 30 days ending today. Pure. */
export function workShareRange(now: Date = new Date()): { from: string; to: string } {
  const from = new Date(now.getTime() - 29 * 86_400_000);
  return { from: isoDay(from), to: isoDay(now) };
}

/** The agents' share as a whole percentage, rounded half up; null while nothing was done. Pure. */
export function sharePercent(share: number | null): number | null {
  if (share === null || !Number.isFinite(share)) return null;
  return Math.round(share * 100);
}

/** A day's agent share as a bar length, 0..100. Pure. */
export function dayBar(day: ShareDay): number {
  const total = day.done_by_agent + day.done_by_person;
  return total === 0 ? 0 : Math.round((day.done_by_agent / total) * 100);
}

/**
 * AK3-T7: work done by agents. Per process (a work measure: a ticket
 * resolved, say), how many completions agents and people made over the
 * range, the hand-offs between them and the agents' share, with a bar per
 * day for the trend. Every count of a day opens the change events behind it,
 * each linked to its record. Logical CSS only; numbers follow the page's
 * locale.
 */
@Component({
  selector: 'xrm-ai-work-share',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, RouterLink, TranslatePipe],
  template: `
    <section class="aws">
      <h2>{{ 'aiWorkShare.title' | translate }}</h2>
      <p class="aws-muted">{{ 'aiWorkShare.intro' | translate }}</p>
      <form class="aws-range" (ngSubmit)="load()">
        <label>{{ 'aiWorkShare.from' | translate }} <input type="date" name="from" [(ngModel)]="from" /></label>
        <label>{{ 'aiWorkShare.to' | translate }} <input type="date" name="to" [(ngModel)]="to" /></label>
        <button type="submit">{{ 'aiWorkShare.show' | translate }}</button>
      </form>
      @if (error(); as message) { <p class="aws-error" role="alert">{{ message }}</p> }

      @for (p of processes(); track p.process_key) {
        <article class="aws-process" [attr.data-process]="p.process_key">
          <header class="aws-head">
            <h3>{{ label(p) }}</h3>
            <strong class="aws-share" data-share>
              @if (p.share !== null) {
                {{ 'aiWorkShare.share' | translate: { pct: num(sharePercent(p.share) ?? 0) } }}
              } @else {
                {{ 'aiWorkShare.noShare' | translate }}
              }
            </strong>
          </header>
          <p class="aws-counts">
            {{ 'aiWorkShare.byAgent' | translate: { count: num(p.done_by_agent) } }} ·
            {{ 'aiWorkShare.byPerson' | translate: { count: num(p.done_by_person) } }} ·
            {{ 'aiWorkShare.handed' | translate: { count: num(p.handed_between) } }}
          </p>
          @if (p.days.length) {
            <ul class="aws-days" [attr.aria-label]="'aiWorkShare.trend' | translate">
              @for (d of p.days; track d.day) {
                <li>
                  <span class="aws-day" dir="ltr">{{ d.day }}</span>
                  <span class="aws-bar" aria-hidden="true"><span [style.inline-size.%]="dayBar(d)"></span></span>
                  <button type="button" class="aws-link" (click)="open(p, d.day, 'agent')">
                    {{ 'aiWorkShare.byAgent' | translate: { count: num(d.done_by_agent) } }}
                  </button>
                  <button type="button" class="aws-link" (click)="open(p, d.day, 'person')">
                    {{ 'aiWorkShare.byPerson' | translate: { count: num(d.done_by_person) } }}
                  </button>
                </li>
              }
            </ul>
          }
        </article>
      } @empty {
        @if (loaded()) { <p class="aws-muted" data-empty>{{ 'aiWorkShare.none' | translate }}</p> }
      }

      @if (eventsFor(); as at) {
        <aside class="aws-events" [attr.aria-label]="'aiWorkShare.events' | translate">
          <div class="aws-head">
            <h3>{{ 'aiWorkShare.eventsOf' | translate: { day: at.day, by: ('aiWorkShare.by.' + at.by | translate) } }}</h3>
            <button type="button" (click)="closeEvents()">{{ 'aiWorkShare.close' | translate }}</button>
          </div>
          <ul>
            @for (e of events(); track e.id) {
              <li>
                <a [routerLink]="['/xrm', e.entity, e.record_id]" dir="ltr">{{ e.entity }} {{ e.record_id }}</a>
                <span class="aws-muted">{{ e.at | localDate: { dateStyle: 'short', timeStyle: 'short' } }}</span>
              </li>
            } @empty {
              <li class="aws-muted">{{ 'aiWorkShare.noEvents' | translate }}</li>
            }
          </ul>
          @if (nextCursor()) {
            <button type="button" (click)="more()">{{ 'aiWorkShare.more' | translate }}</button>
          }
        </aside>
      }
    </section>
  `,
  styles: [`
    :host { display: block; padding-block: 1rem; padding-inline: 1rem; }
    .aws { display: flex; flex-direction: column; gap: 0.75rem; max-inline-size: 64rem; }
    .aws h2 { margin-block: 0; font-size: 1.125rem; }
    .aws-range { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: end; }
    .aws-range label { display: flex; flex-direction: column; gap: 0.25rem; }
    .aws-process, .aws-events { border: 1px solid var(--color-border); border-radius: 0.5rem;
      padding-block: 0.75rem; padding-inline: 0.75rem; display: flex; flex-direction: column; gap: 0.5rem; }
    .aws-head { display: flex; align-items: center; gap: 0.75rem; }
    .aws-head h3 { flex: 1 1 auto; margin-block: 0; font-size: 1rem; }
    .aws-counts { margin-block: 0; }
    .aws-days, .aws-events ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.25rem; }
    .aws-days li, .aws-events li { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
    .aws-day { min-inline-size: 7rem; }
    .aws-bar { inline-size: 8rem; block-size: 0.5rem; background: var(--color-bg-alt); border-radius: 0.25rem; overflow: hidden; }
    .aws-bar span { display: block; block-size: 100%; background: var(--color-primary); }
    .aws-link { background: none; border: none; padding: 0; color: var(--color-primary); cursor: pointer; font: inherit; }
    .aws-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .aws-error { color: var(--color-danger); }
  `],
})
export class AiWorkShareComponent implements OnInit {
  private readonly workShare = inject(AiWorkShareService);
  private readonly lang = inject(LangService);

  from = workShareRange().from;
  to = workShareRange().to;

  readonly processes = signal<ProcessShare[]>([]);
  readonly loaded = signal(false);
  readonly error = signal<string | null>(null);
  readonly eventsFor = signal<{ process: string; day: string; by: DoneBy } | null>(null);
  readonly events = signal<ShareEvent[]>([]);
  readonly nextCursor = signal<string | null>(null);

  readonly sharePercent = sharePercent;
  readonly dayBar = dayBar;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.error.set(null);
    this.workShare.summary(this.from, this.to).subscribe({
      next: page => {
        this.processes.set(page.items ?? []);
        this.loaded.set(true);
      },
      error: (e: ApiError) => {
        this.loaded.set(true);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  /** The process's label in the page's language. */
  label(p: ProcessShare): string {
    const arabic = this.lang.current() === 'ar' ? p.label_ar : null;
    return arabic || p.label || p.process_key;
  }

  num(value: number): string {
    return new Intl.NumberFormat(this.lang.intlLocale()).format(value);
  }

  open(p: ProcessShare, day: string, by: DoneBy): void {
    this.eventsFor.set({ process: p.process_key, day, by });
    this.events.set([]);
    this.nextCursor.set(null);
    this.fetchEvents(null);
  }

  more(): void {
    this.fetchEvents(this.nextCursor());
  }

  closeEvents(): void {
    this.eventsFor.set(null);
    this.events.set([]);
    this.nextCursor.set(null);
  }

  private fetchEvents(cursor: string | null): void {
    const at = this.eventsFor();
    if (!at) return;
    this.workShare.events(at.process, at.day, at.by, cursor).subscribe({
      next: page => {
        this.events.set([...this.events(), ...(page.items ?? [])]);
        this.nextCursor.set(page.next_cursor ?? null);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }
}
