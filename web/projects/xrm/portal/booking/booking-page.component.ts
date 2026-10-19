import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, LangService, TranslatePipe } from '@attome/base';
import { BookingPageView, challengeToken, groupByDay, meetingTime, ownTimeZone, timeZones } from './booking';

type Stage = 'loading' | 'ready' | 'booking' | 'booked' | 'missing' | 'taken' | 'failed';

/**
 * D20-T2/T3: the public booking page at `/book/:slug`. No session: it lists
 * the times someone on the team is free, in the visitor's language (Arabic
 * right to left, with a toggle) and in the time zone they pick (their own by
 * default). It says what kind of meeting it is (video and on which service,
 * a phone call, or in person and where), takes a name and email, solves the
 * deployment's proof-of-work challenge when one is in force, and books. The
 * confirmation email carries the link to reschedule or cancel. Logical CSS
 * only.
 */
@Component({
  selector: 'xrm-book-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <main class="bk" [attr.dir]="dir()" [attr.lang]="lang.current()">
      <section class="bk-card" aria-labelledby="bk-title">
        <div class="bk-head">
          <h1 id="bk-title">{{ page()?.name || ('book.title' | translate) }}</h1>
          <button type="button" class="bk-lang" (click)="toggleLanguage()">{{ 'book.otherLanguage' | translate }}</button>
        </div>
        @switch (stage()) {
          @case ('loading') { <p class="bk-muted" role="status">{{ 'book.loading' | translate }}</p> }
          @case ('missing') { <p class="bk-error" role="alert" data-testid="book-missing">{{ 'book.notFound' | translate }}</p> }
          @case ('booked') {
            <p class="bk-done" role="status" data-testid="book-done">{{ 'book.booked' | translate }}</p>
            <p class="bk-when"><bdi>{{ chosenTime() }}</bdi></p>
            <p class="bk-muted">{{ 'book.checkEmail' | translate }}</p>
          }
          @default {
            @if (page(); as p) {
              @if (p.description) { <p class="bk-muted">{{ p.description }}</p> }
              <p class="bk-muted">{{ 'book.length' | translate }}: <span class="num">{{ p.duration_minutes }}</span></p>
              @if (p.meeting_type) {
                <p class="bk-muted" data-testid="book-type">
                  {{ ('book.meetingType.' + p.meeting_type) | translate }}
                  @if (p.meeting_type === 'video' && p.video_provider) {
                    · {{ ('book.provider.' + p.video_provider) | translate }}
                  }
                  @if (p.location) { · {{ 'book.where' | translate }}: <bdi>{{ p.location }}</bdi> }
                </p>
              }
              <label class="bk-tz">{{ 'book.timeZone' | translate }}
                <select [value]="zone()" (change)="zone.set($any($event.target).value)" data-testid="book-zone">
                  @for (z of zones; track z) { <option [value]="z">{{ z }}</option> }
                </select>
              </label>
              @if (days().length === 0) {
                <p data-testid="book-none">{{ 'book.noTimes' | translate }}</p>
              }
              <div class="bk-days">
                @for (d of days(); track d.key) {
                  <div class="bk-day" data-testid="book-day">
                    <h2>{{ d.label }}</h2>
                    <div class="bk-slots">
                      @for (s of d.slots; track s.start) {
                        <button type="button" class="bk-slot" [class.bk-chosen]="chosen() === s.start"
                                [attr.aria-pressed]="chosen() === s.start" (click)="choose(s.start)"
                                data-testid="book-slot">{{ s.label }}</button>
                      }
                    </div>
                  </div>
                }
              </div>
              @if (chosen()) {
                <form class="bk-form" (ngSubmit)="book()" data-testid="book-form">
                  <p class="bk-when"><bdi>{{ chosenTime() }}</bdi></p>
                  <label>{{ 'book.name' | translate }}
                    <input name="name" [(ngModel)]="name" required maxlength="200" autocomplete="name" />
                  </label>
                  <label>{{ 'book.email' | translate }}
                    <input name="email" type="email" [(ngModel)]="email" required maxlength="254" autocomplete="email" />
                  </label>
                  <label>{{ 'book.phone' | translate }}
                    <input name="phone" type="tel" [(ngModel)]="phone" maxlength="40" autocomplete="tel" />
                  </label>
                  <label>{{ 'book.notes' | translate }}
                    <textarea name="notes" rows="3" [(ngModel)]="notes" maxlength="2000"></textarea>
                  </label>
                  @if (stage() === 'taken') {
                    <p class="bk-error" role="alert" data-testid="book-taken">{{ 'book.taken' | translate }}</p>
                  }
                  @if (stage() === 'failed') {
                    <p class="bk-error" role="alert">{{ 'book.failed' | translate }}</p>
                  }
                  <button type="submit" class="bk-button" [disabled]="stage() === 'booking' || !name.trim() || !email.trim()"
                          data-testid="book-submit">
                    {{ (stage() === 'booking' ? 'book.booking' : 'book.confirm') | translate }}
                  </button>
                </form>
              }
            }
          }
        }
      </section>
    </main>
  `,
  styles: [`
    :host { display: block; min-block-size: 100vh; background: var(--color-bg-secondary, #f6f7f9); }
    .bk { display: flex; justify-content: center; padding-block: 2rem; padding-inline: 1rem; }
    .bk-card { inline-size: 100%; max-inline-size: 40rem; background: var(--color-bg, #fff);
      border: 1px solid var(--color-border, #e3e5e8); border-radius: 0.75rem;
      padding-block: 1.5rem; padding-inline: 1.5rem; display: flex; flex-direction: column; gap: 1rem; }
    .bk-head { display: flex; justify-content: space-between; align-items: center; gap: 1rem; }
    .bk-head h1 { margin-block: 0; font-size: 1.25rem; }
    .bk-lang { background: none; border: none; color: var(--color-accent, #2563eb); cursor: pointer; }
    .bk-days { display: flex; flex-direction: column; gap: 0.75rem; }
    .bk-tz { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; color: var(--color-text-secondary, #5b616b); }
    .bk-tz select { padding-block: 0.375rem; padding-inline: 0.5rem; border: 1px solid var(--color-border, #e3e5e8);
      border-radius: 0.5rem; font: inherit; max-inline-size: 100%; }
    .bk-day h2 { margin-block: 0 0.375rem; font-size: 0.9375rem; }
    .bk-slots { display: flex; flex-wrap: wrap; gap: 0.375rem; }
    .bk-slot { padding-block: 0.375rem; padding-inline: 0.75rem; border: 1px solid var(--color-border, #e3e5e8);
      border-radius: 0.5rem; background: var(--color-bg, #fff); color: inherit; cursor: pointer;
      font-variant-numeric: tabular-nums; }
    .bk-chosen { border-color: var(--color-accent, #2563eb); background: var(--color-accent, #2563eb);
      color: var(--color-on-accent, #fff); }
    .bk-form { display: flex; flex-direction: column; gap: 0.625rem; }
    .bk-form label { display: flex; flex-direction: column; gap: 0.25rem; }
    .bk-form input, .bk-form textarea { padding-block: 0.5rem; padding-inline: 0.625rem;
      border: 1px solid var(--color-border, #e3e5e8); border-radius: 0.5rem; font: inherit; }
    .bk-button { padding-block: 0.75rem; padding-inline: 1rem; border: none; border-radius: 0.5rem;
      background: var(--color-accent, #2563eb); color: var(--color-on-accent, #fff); font-size: 1rem; cursor: pointer; }
    .bk-button[disabled] { opacity: 0.6; cursor: not-allowed; }
    .bk-when { margin-block: 0; font-weight: 600; }
    .bk-muted { margin-block: 0; color: var(--color-text-secondary, #5b616b); }
    .bk-error { margin-block: 0; color: var(--color-danger, #b42318); }
    .bk-done { margin-block: 0; font-size: 1.125rem; font-weight: 600; }
    .num { font-variant-numeric: tabular-nums; unicode-bidi: isolate; }
  `],
})
export class BookPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  protected readonly lang = inject(LangService);

  /** The page's link name, from the route. */
  readonly slug = input.required<string>();

  readonly stage = signal<Stage>('loading');
  readonly page = signal<BookingPageView | null>(null);
  readonly chosen = signal<string | null>(null);
  readonly dir = computed(() => (this.lang.isRtl() ? 'rtl' : 'ltr'));
  /** D20-T3: the zone times are shown in; the visitor's own to start. */
  readonly zone = signal(ownTimeZone());
  readonly zones = timeZones(this.zone());
  readonly days = computed(() => groupByDay(this.page()?.slots ?? [], this.lang.intlLocale(), this.zone()));
  readonly chosenTime = computed(() => {
    const start = this.chosen();
    const slot = this.page()?.slots.find(s => s.start === start);
    return slot ? meetingTime(slot.start, slot.end, this.lang.intlLocale(), this.zone()) : '';
  });

  name = '';
  email = '';
  phone = '';
  notes = '';

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.api.get<BookingPageView>(`/api/v1/booking/${encodeURIComponent(this.slug())}`).subscribe({
      next: page => {
        this.page.set(page);
        if (this.stage() === 'loading') this.stage.set('ready');
      },
      error: () => this.stage.set('missing'),
    });
  }

  toggleLanguage(): void {
    void this.lang.toggle();
  }

  choose(start: string): void {
    this.chosen.set(start);
    if (this.stage() !== 'booking') this.stage.set('ready');
  }

  async book(): Promise<void> {
    const start = this.chosen();
    if (!start || this.stage() === 'booking') return;
    this.stage.set('booking');
    const captcha_token = await challengeToken(this.api);
    this.api.post(`/api/v1/booking/${encodeURIComponent(this.slug())}`, {
      start, name: this.name.trim(), email: this.email.trim(),
      phone: this.phone.trim() || null, notes: this.notes.trim() || null, captcha_token,
    }).subscribe({
      next: () => this.stage.set('booked'),
      error: (err: { status?: number }) => {
        if (err?.status === 409) {
          // Someone took it first: show the times that are still free.
          this.stage.set('taken');
          this.chosen.set(null);
          this.load();
        } else {
          this.stage.set('failed');
        }
      },
    });
  }
}
