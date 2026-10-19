import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { ApiService, LangService, TranslatePipe } from '@attome/base';
import { BookingPageView, ManagedBooking, groupByDay, meetingTime, ownTimeZone } from './booking';

type Stage = 'loading' | 'ready' | 'busy' | 'missing' | 'failed' | 'taken';

/**
 * D20-T2: the reschedule/cancel page at `/book/manage/:token`, reached from
 * the confirmation email. The signed token is the only authority; an altered
 * or expired one shows a message and nobody's booking.
 */
@Component({
  selector: 'app-book-manage',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <main class="bk" [attr.dir]="dir()" [attr.lang]="lang.current()">
      <section class="bk-card" aria-labelledby="bm-title">
        <div class="bk-head">
          <h1 id="bm-title">{{ booking()?.page_name || ('book.title' | translate) }}</h1>
          <button type="button" class="bk-lang" (click)="toggleLanguage()">{{ 'book.otherLanguage' | translate }}</button>
        </div>
        @switch (stage()) {
          @case ('loading') { <p class="bk-muted" role="status">{{ 'book.loading' | translate }}</p> }
          @case ('missing') { <p class="bk-error" role="alert" data-testid="manage-missing">{{ 'book.linkInvalid' | translate }}</p> }
          @default {
            @if (booking(); as b) {
              <p class="bk-when" data-testid="manage-when"><bdi>{{ when() }}</bdi></p>
              @if (b.status === 'cancelled') {
                <p class="bk-muted" data-testid="manage-cancelled">{{ 'book.cancelled' | translate }}</p>
              } @else {
                @if (stage() === 'failed') { <p class="bk-error" role="alert">{{ 'book.failed' | translate }}</p> }
                @if (stage() === 'taken') { <p class="bk-error" role="alert">{{ 'book.taken' | translate }}</p> }
                <div class="bk-actions">
                  <button type="button" class="bk-button" (click)="showTimes()" [disabled]="stage() === 'busy'"
                          data-testid="manage-reschedule">{{ 'book.reschedule' | translate }}</button>
                  <button type="button" class="bk-secondary" (click)="cancel()" [disabled]="stage() === 'busy'"
                          data-testid="manage-cancel">{{ 'book.cancel' | translate }}</button>
                </div>
                @for (d of days(); track d.key) {
                  <div class="bk-day">
                    <h2>{{ d.label }}</h2>
                    <div class="bk-slots">
                      @for (s of d.slots; track s.start) {
                        <button type="button" class="bk-slot" (click)="moveTo(s.start)" [disabled]="stage() === 'busy'"
                                data-testid="manage-slot">{{ s.label }}</button>
                      }
                    </div>
                  </div>
                }
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
    .bk-actions { display: flex; flex-wrap: wrap; gap: 0.5rem; }
    .bk-day h2 { margin-block: 0 0.375rem; font-size: 0.9375rem; }
    .bk-slots { display: flex; flex-wrap: wrap; gap: 0.375rem; }
    .bk-slot, .bk-secondary { padding-block: 0.375rem; padding-inline: 0.75rem;
      border: 1px solid var(--color-border, #e3e5e8); border-radius: 0.5rem; background: var(--color-bg, #fff);
      color: inherit; cursor: pointer; }
    .bk-button { padding-block: 0.375rem; padding-inline: 0.75rem; border: none; border-radius: 0.5rem;
      background: var(--color-accent, #2563eb); color: var(--color-on-accent, #fff); cursor: pointer; }
    .bk-when { margin-block: 0; font-weight: 600; }
    .bk-muted { margin-block: 0; color: var(--color-text-secondary, #5b616b); }
    .bk-error { margin-block: 0; color: var(--color-danger, #b42318); }
  `],
})
export class BookManageComponent implements OnInit {
  private readonly api = inject(ApiService);
  protected readonly lang = inject(LangService);

  /** The signed manage token, from the route. */
  readonly token = input.required<string>();

  readonly stage = signal<Stage>('loading');
  readonly booking = signal<ManagedBooking | null>(null);
  readonly slots = signal<{ start: string; end: string }[]>([]);
  readonly dir = computed(() => (this.lang.isRtl() ? 'rtl' : 'ltr'));
  private readonly zone = ownTimeZone();
  readonly days = computed(() => groupByDay(this.slots(), this.lang.intlLocale(), this.zone));
  readonly when = computed(() => {
    const b = this.booking();
    return b ? `${meetingTime(b.start, b.end, this.lang.intlLocale(), this.zone)} (${this.zone})` : '';
  });

  private path(suffix = ''): string {
    return `/api/v1/booking/manage/${encodeURIComponent(this.token())}${suffix}`;
  }

  ngOnInit(): void {
    this.api.get<ManagedBooking>(this.path()).subscribe({
      next: b => {
        this.booking.set(b);
        this.stage.set('ready');
      },
      error: () => this.stage.set('missing'),
    });
  }

  toggleLanguage(): void {
    void this.lang.toggle();
  }

  showTimes(): void {
    const slug = this.booking()?.slug;
    if (!slug) return;
    this.api.get<BookingPageView>(`/api/v1/booking/${encodeURIComponent(slug)}`).subscribe({
      next: page => this.slots.set(page.slots),
      error: () => this.stage.set('failed'),
    });
  }

  cancel(): void {
    this.send(this.path('/cancel'), {});
  }

  moveTo(start: string): void {
    this.send(this.path('/reschedule'), { start });
  }

  private send(path: string, body: object): void {
    this.stage.set('busy');
    this.api.post<ManagedBooking>(path, body).subscribe({
      next: b => {
        this.booking.set(b);
        this.slots.set([]);
        this.stage.set('ready');
      },
      error: (err: { status?: number }) => this.stage.set(err?.status === 409 ? 'taken' : 'failed'),
    });
  }
}
