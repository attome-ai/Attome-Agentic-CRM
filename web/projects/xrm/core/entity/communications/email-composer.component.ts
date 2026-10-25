import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, output, signal, untracked,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';

import { EntityService } from '../services/entity.service';

/** A reply template suggested for the record (`/api/v1/model/reply-suggestions`). */
export interface ComposerTemplate {
  id: string;
  name: string;
  folder: string | null;
  reply: string;
}

/** One of the record's files that can go with the email. */
export interface RecordFile {
  key: string;
  name: string;
}

/** The compose body (`ComposeRequest`). */
export interface ComposeBody {
  channel: 'email';
  to: string[];
  subject: string;
  body: string;
  send_at?: string;
  attachments?: string[];
}

/** Addresses split on commas, semicolons and spaces. Pure. */
export function splitAddresses(text: string): string[] {
  return text.split(/[\s,;]+/).map(a => a.trim()).filter(Boolean);
}

/** A `datetime-local` value as an instant, or null when empty or invalid. Pure. */
export function sendAtInstant(local: string): string | null {
  if (!local) return null;
  const at = new Date(local);
  return Number.isNaN(at.getTime()) ? null : at.toISOString();
}

/** The request a composed email makes. Pure. */
export function composeBody(
  to: string, subject: string, body: string, sendAt: string, files: readonly string[],
): ComposeBody {
  const request: ComposeBody = { channel: 'email', to: splitAddresses(to), subject: subject.trim(), body };
  const at = sendAtInstant(sendAt);
  if (at) request.send_at = at;
  if (files.length) request.attachments = [...files];
  return request;
}

/**
 * J1-T2: an email from a record. Pick a reply template to fill the body,
 * tick any of the record's own files to attach, and optionally choose a
 * time to send it later. It goes out through the record's compose route
 * (J1-T1), so it threads, carries the author's signature and lands on the
 * record's timeline.
 */
@Component({
  selector: 'xrm-email-composer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <form class="ec" (submit)="send($event)" [attr.aria-label]="'emailComposer.title' | translate" data-testid="email-composer">
      <label class="ec-field">
        <span>{{ 'emailComposer.to' | translate }}</span>
        <input type="text" dir="ltr" [value]="to()" (input)="to.set($any($event.target).value)" data-testid="ec-to" />
      </label>
      <label class="ec-field">
        <span>{{ 'emailComposer.subject' | translate }}</span>
        <input type="text" dir="auto" [value]="subject()" (input)="subject.set($any($event.target).value)" data-testid="ec-subject" />
      </label>
      @if (templates().length) {
        <label class="ec-field">
          <span>{{ 'emailComposer.template' | translate }}</span>
          <select (change)="useTemplate($any($event.target).value); $any($event.target).value = ''" data-testid="ec-template">
            <option value="">{{ 'emailComposer.chooseTemplate' | translate }}</option>
            @for (t of templates(); track t.id) {
              <option [value]="t.id">{{ t.folder ? t.folder + ' / ' + t.name : t.name }}</option>
            }
          </select>
        </label>
      }
      <label class="ec-field">
        <span>{{ 'emailComposer.body' | translate }}</span>
        <textarea rows="8" dir="auto" [value]="body()" (input)="body.set($any($event.target).value)" data-testid="ec-body"></textarea>
      </label>
      @if (files().length) {
        <fieldset class="ec-files">
          <legend>{{ 'emailComposer.attach' | translate }}</legend>
          @for (f of files(); track f.key) {
            <label class="ec-file">
              <input type="checkbox" [checked]="chosen().includes(f.key)" (change)="toggleFile(f.key)"
                     [attr.data-testid]="'ec-file-' + f.name" />
              <i class="las la-paperclip" aria-hidden="true"></i> {{ f.name }}
            </label>
          }
        </fieldset>
      }
      <label class="ec-field ec-later">
        <span>{{ 'emailComposer.sendLater' | translate }}</span>
        <input type="datetime-local" [value]="sendAt()" (input)="sendAt.set($any($event.target).value)" data-testid="ec-send-at" />
      </label>
      <div class="ec-row">
        @if (notice(); as message) { <span class="ec-notice" role="status" data-testid="ec-notice">{{ message }}</span> }
        <button type="submit" class="btn-primary" [disabled]="!canSend()" data-testid="ec-send">
          {{ (sending() ? 'emailComposer.sending' : (sendAt() ? 'emailComposer.schedule' : 'emailComposer.send')) | translate }}
        </button>
      </div>
    </form>
  `,
  styles: [`
    .ec { display: grid; gap: 0.6rem; }
    .ec-field { display: grid; gap: 0.25rem; }
    .ec-field input, .ec-field textarea, .ec-field select { inline-size: 100%; font: inherit; }
    .ec-files { display: grid; gap: 0.3rem; border: 1px solid var(--color-border); border-radius: 6px; padding-block: 0.5rem; padding-inline: 0.75rem; }
    .ec-file { display: flex; gap: 0.4rem; align-items: center; }
    .ec-later { max-inline-size: 18rem; }
    .ec-row { display: flex; justify-content: flex-end; align-items: center; gap: 0.75rem; }
    .ec-notice { font-size: 12px; color: var(--color-text-secondary); }
  `],
})
export class EmailComposerComponent {
  private readonly api = inject(ApiService);
  private readonly entities = inject(EntityService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly entity = input.required<string>();
  readonly recordId = input.required<string>();
  /** The address to start with, when the record has one. */
  readonly defaultTo = input<string>('');
  /** An email went out (or was scheduled). */
  readonly sent = output<void>();

  readonly to = signal('');
  readonly subject = signal('');
  readonly body = signal('');
  readonly sendAt = signal('');
  readonly templates = signal<ComposerTemplate[]>([]);
  readonly files = signal<RecordFile[]>([]);
  readonly chosen = signal<string[]>([]);
  readonly sending = signal(false);
  readonly notice = signal<string | null>(null);

  readonly canSend = computed(() =>
    !this.sending() && splitAddresses(this.to()).length > 0 && !!this.subject().trim() && !!this.body().trim());

  constructor() {
    effect(() => {
      const start = this.defaultTo();
      untracked(() => { if (!this.to()) this.to.set(start); });
    });
    effect(() => {
      const entity = this.entity();
      const recordId = this.recordId();
      untracked(() => this.load(entity, recordId));
    });
  }

  private load(entity: string, recordId: string): void {
    this.api.get<{ items: ComposerTemplate[] }>('/api/v1/model/reply-suggestions', {
      entity, record_id: recordId, channel: 'email',
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: page => this.templates.set(page.items),
      error: () => this.templates.set([]),
    });
    this.entities.list('attome_document', {
      filters: [
        { field: 'entity_name', op: 'eq', value: entity },
        { field: 'record_id', op: 'eq', value: recordId },
      ],
      limit: 50,
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => this.files.set(res.data
        .map(r => r.data as Record<string, unknown>)
        .filter(d => typeof d['file'] === 'string' && d['file'])
        .map(d => ({ key: String(d['file']), name: String(d['name'] ?? d['file']) }))),
      error: () => this.files.set([]),
    });
  }

  /** Puts the template's text in the body (after what is there) and counts the use. */
  useTemplate(id: string): void {
    const t = this.templates().find(x => x.id === id);
    if (!t) return;
    const current = this.body();
    this.body.set(current.trim() ? `${current.trimEnd()}\n\n${t.reply}` : t.reply);
    this.api.post<void>(`/api/v1/model/reply-templates/${t.id}/used`, {
      entity: this.entity(), record_id: this.recordId(),
    }).subscribe({ error: () => undefined });
  }

  toggleFile(key: string): void {
    this.chosen.update(list => (list.includes(key) ? list.filter(k => k !== key) : [...list, key]));
  }

  send(event: Event): void {
    event.preventDefault();
    if (!this.canSend()) return;
    this.sending.set(true);
    this.notice.set(null);
    const later = !!sendAtInstant(this.sendAt());
    const request = composeBody(this.to(), this.subject(), this.body(), this.sendAt(), this.chosen());
    this.api.post<unknown>(`/api/v1/${this.entity()}/${this.recordId()}/communications`, request).subscribe({
      next: () => {
        this.sending.set(false);
        this.subject.set('');
        this.body.set('');
        this.sendAt.set('');
        this.chosen.set([]);
        this.notice.set(this.lang.translate(later ? 'emailComposer.scheduled' : 'emailComposer.sent'));
        this.sent.emit();
      },
      error: (e: ApiError) => {
        this.sending.set(false);
        this.notice.set(e.message || this.lang.translate('emailComposer.failed'));
      },
    });
  }
}
