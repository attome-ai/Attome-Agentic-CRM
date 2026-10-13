import { ChangeDetectionStrategy, Component, inject, input, signal } from '@angular/core';
import { ApiError, AuthService, LangService, TranslatePipe } from '@attome/base';
import { EntityService } from '../services/entity.service';

/** The platform entity a reminder is stored in (`platform-bundles/xrm-reminder.json`). */
export const REMINDER_ENTITY = 'reminder';
const MAX_NOTE_LENGTH = 1000;

/**
 * "Remind me" (U4, D-602) on the record form header: a date/time and an
 * optional note, saved as an `reminder` for the signed-in user. The
 * notification poller delivers it at that time as an ordinary notification,
 * so it shows up in the bell like any other.
 *
 * The server decides everything that matters: the recipient must be the
 * creator (admins excepted), the caller must be able to read the record, and
 * a reminder whose record later becomes hidden is dismissed, not delivered.
 */
@Component({
  selector: 'xrm-remind-me',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./remind-me.component.css'],
  templateUrl: './remind-me.component.html',
})
export class RemindMeComponent {
  private readonly entities = inject(EntityService);
  private readonly auth     = inject(AuthService);
  private readonly lang     = inject(LangService);

  /** Logical name of the record's entity. */
  readonly entity   = input.required<string>();
  /** The record's id. */
  readonly recordId = input.required<string>();

  readonly open    = signal(false);
  readonly when    = signal('');
  readonly note    = signal('');
  readonly saving  = signal(false);
  readonly error   = signal<string | null>(null);
  readonly notice  = signal<string | null>(null);

  readonly maxNoteLength = MAX_NOTE_LENGTH;

  toggle(): void {
    const opening = !this.open();
    this.open.set(opening);
    this.error.set(null);
    if (opening) {
      this.notice.set(null);
      if (!this.when()) this.when.set(this.defaultWhen());
    }
  }

  onWhen(event: Event): void { this.when.set((event.target as HTMLInputElement).value); }
  onNote(event: Event): void { this.note.set((event.target as HTMLTextAreaElement).value); }

  save(): void {
    const userId = this.auth.userId();
    const at = this.when() ? new Date(this.when()) : null;
    if (!userId || !at || Number.isNaN(at.getTime())) {
      this.error.set(this.lang.translate('reminders.error.when'));
      return;
    }
    if (at.getTime() <= Date.now()) {
      this.error.set(this.lang.translate('reminders.error.past'));
      return;
    }
    const note = this.note().trim().slice(0, MAX_NOTE_LENGTH);
    this.saving.set(true);
    this.error.set(null);
    this.entities.create(REMINDER_ENTITY, {
      user_ref:    userId,
      entity_name: this.entity(),
      record_id:   this.recordId(),
      remind_at:   at.toISOString(),
      note:        note || null,
      status:      'pending',
    }).subscribe({
      next: () => {
        this.saving.set(false);
        this.open.set(false);
        this.note.set('');
        this.when.set('');
        this.notice.set(this.lang.translate('reminders.saved'));
      },
      error: (e: ApiError) => {
        this.saving.set(false);
        this.error.set(this.errorText(e));
      },
    });
  }

  /** One hour from now, as a `datetime-local` value in the browser's zone. */
  private defaultWhen(): string {
    const d = new Date(Date.now() + 60 * 60 * 1000);
    d.setSeconds(0, 0);
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  private errorText(e: ApiError): string {
    switch (e.kind) {
      case 'forbidden': return this.lang.translate('reminders.error.forbidden');
      case 'not_found': return this.lang.translate('reminders.error.notFound');
      default:          return e.message || this.lang.translate('reminders.error.failed');
    }
  }
}
