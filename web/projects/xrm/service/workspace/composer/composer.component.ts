import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal } from '@angular/core';
import { ApiService, LangService, TranslatePipe } from '@attome/base';

/** A reply template suggested for the record (G6-T3, `Suggestion`). */
export interface ReplyTemplate {
  id: string;
  name: string;
  folder: string | null;
  reply: string;
}

export type ComposerChannel = 'email' | 'note';

/** The `/query` being typed at the start of a line, or null. Pure. */
export function slashQuery(text: string, caret: number): { start: number; query: string } | null {
  const before = text.slice(0, caret);
  const lineStart = before.lastIndexOf('\n') + 1;
  const line = before.slice(lineStart);
  if (!line.startsWith('/') || /\s/.test(line)) return null;
  return { start: lineStart, query: line.slice(1).toLowerCase() };
}

/** Templates whose name (or folder/name) contains the query. Pure. */
export function matchTemplates(templates: ReplyTemplate[], query: string): ReplyTemplate[] {
  const q = query.trim().toLowerCase();
  return templates
    .filter(t => !q || t.name.toLowerCase().includes(q) || (t.folder ?? '').toLowerCase().includes(q))
    .slice(0, 6);
}

/**
 * G5-T2: one composer for a case. The agent picks the channel — an email to
 * the customer or an internal note on the record — and types `/` and part of
 * a name at the start of a line to insert a reply template (G6), rendered for
 * the case. Sending goes through the ordinary record routes, so the message
 * lands on the record's timeline with its audit.
 */
@Component({
  selector: 'xrm-service-composer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <form class="cp" (submit)="send($event)" [attr.aria-label]="'composer.title' | translate">
      <div class="cp-channels" role="radiogroup" [attr.aria-label]="'composer.channel' | translate">
        @for (c of channels; track c) {
          <label class="cp-channel">
            <input type="radio" name="cp-channel" [value]="c" [checked]="channel() === c"
                   (change)="channel.set(c)" [attr.data-testid]="'composer-channel-' + c" />
            {{ ('composer.channels.' + c) | translate }}
          </label>
        }
      </div>
      @if (channel() === 'email') {
        <input type="email" class="cp-input" [value]="to()" (input)="to.set($any($event.target).value)"
               [placeholder]="'composer.to' | translate" [attr.aria-label]="'composer.to' | translate"
               data-testid="composer-to" />
      }
      <input type="text" class="cp-input" [value]="subject()" (input)="subject.set($any($event.target).value)"
             [placeholder]="(channel() === 'email' ? 'composer.subject' : 'composer.noteTitle') | translate"
             data-testid="composer-subject" />
      <textarea #box class="cp-input" rows="5" [value]="body()"
                (input)="onInput($any($event.target))" (keydown)="onKey($event, box)"
                [placeholder]="'composer.bodyHint' | translate" [attr.aria-label]="'composer.body' | translate"
                data-testid="composer-body"></textarea>
      @if (matches().length) {
        <ul class="cp-templates" role="listbox" [attr.aria-label]="'composer.templates' | translate" data-testid="composer-templates">
          @for (t of matches(); track t.id; let i = $index) {
            <li role="option" [attr.aria-selected]="i === active()" [class.cp-active]="i === active()"
                (mousedown)="$event.preventDefault(); insert(t, box)" data-testid="composer-template">
              <strong>{{ t.name }}</strong>
              @if (t.folder) { <span class="cp-hint">{{ t.folder }}</span> }
            </li>
          }
        </ul>
      }
      <div class="cp-row">
        @if (notice(); as message) { <span class="cp-hint" role="status" data-testid="composer-notice">{{ message }}</span> }
        <button type="submit" class="cp-send" [disabled]="!canSend()" data-testid="composer-send">
          {{ (sending() ? 'composer.sending' : 'composer.send') | translate }}
        </button>
      </div>
    </form>
  `,
  styles: [`
    .cp { display: grid; gap: 8px; }
    .cp-channels { display: flex; gap: 12px; }
    .cp-channel { display: inline-flex; align-items: center; gap: 4px; }
    .cp-input { inline-size: 100%; padding-block: 6px; padding-inline: 8px; border: 1px solid var(--color-border);
                border-radius: 6px; background: var(--color-bg); color: var(--color-text-primary); font: inherit; }
    textarea.cp-input { resize: vertical; }
    .cp-templates { list-style: none; margin: 0; padding: 0; border: 1px solid var(--color-border); border-radius: 6px; }
    .cp-templates li { padding-block: 6px; padding-inline: 10px; cursor: pointer; display: flex; gap: 8px; }
    .cp-active, .cp-templates li:hover { background: var(--color-bg-alt); }
    .cp-row { display: flex; justify-content: flex-end; align-items: center; gap: 12px; }
    .cp-hint { font-size: 12px; color: var(--color-text-secondary); }
    .cp-send { padding-block: 6px; padding-inline: 14px; border: none; border-radius: 6px; cursor: pointer;
               background: var(--color-accent); color: var(--color-bg); font-weight: 700; }
    .cp-send:disabled { opacity: .5; cursor: not-allowed; }
  `],
})
export class ComposerComponent {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  /** The case's entity and id. */
  readonly entity = input.required<string>();
  readonly recordId = input.required<string>();
  /** The customer's address, when known. */
  readonly defaultTo = input<string>('');

  /** A message was sent or a note saved. */
  readonly sent = output<ComposerChannel>();

  readonly channels: ComposerChannel[] = ['email', 'note'];
  readonly channel = signal<ComposerChannel>('email');
  readonly to = signal('');
  readonly subject = signal('');
  readonly body = signal('');
  readonly sending = signal(false);
  readonly notice = signal<string | null>(null);
  readonly templates = signal<ReplyTemplate[]>([]);
  readonly query = signal<{ start: number; query: string } | null>(null);
  readonly active = signal(0);

  readonly matches = computed(() => {
    const q = this.query();
    return q ? matchTemplates(this.templates(), q.query) : [];
  });
  readonly canSend = computed(() =>
    !this.sending() && !!this.body().trim() && (this.channel() === 'note' || !!this.to().trim()));

  constructor() {
    effect(() => this.to.set(this.defaultTo()));
    effect(() => {
      const entity = this.entity();
      const recordId = this.recordId();
      const channel = this.channel() === 'note' ? 'portal' : 'email';
      this.api.get<{ items: ReplyTemplate[] }>('/api/v1/model/reply-suggestions', {
        entity, record_id: recordId, channel,
      }).subscribe({
        next: page => this.templates.set(page.items),
        error: () => this.templates.set([]),
      });
    });
  }

  onInput(box: HTMLTextAreaElement): void {
    this.body.set(box.value);
    this.query.set(slashQuery(box.value, box.selectionStart ?? box.value.length));
    this.active.set(0);
  }

  onKey(event: KeyboardEvent, box: HTMLTextAreaElement): void {
    const found = this.matches();
    if (!found.length) return;
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const n = found.length;
      this.active.update(i => (event.key === 'ArrowDown' ? (i + 1) % n : (i - 1 + n) % n));
    } else if (event.key === 'Enter' || event.key === 'Tab') {
      event.preventDefault();
      this.insert(found[this.active()], box);
    } else if (event.key === 'Escape') {
      this.query.set(null);
    }
  }

  /** Puts a template's reply where the `/query` is, and counts the use. */
  insert(t: ReplyTemplate, box: HTMLTextAreaElement): void {
    const q = this.query();
    if (!q) return;
    const text = this.body();
    const end = q.start + 1 + q.query.length;
    const next = text.slice(0, q.start) + t.reply + text.slice(end);
    this.body.set(next);
    box.value = next;
    const caret = q.start + t.reply.length;
    box.setSelectionRange(caret, caret);
    this.query.set(null);
    this.api.post<void>(`/api/v1/model/reply-templates/${t.id}/used`, {
      entity: this.entity(), record_id: this.recordId(),
    }).subscribe({ error: () => undefined });
  }

  send(event: Event): void {
    event.preventDefault();
    if (!this.canSend()) return;
    this.sending.set(true);
    this.notice.set(null);
    const channel = this.channel();
    const request = channel === 'email'
      ? this.api.post<unknown>(`/api/v1/${this.entity()}/${this.recordId()}/communications`, {
          channel: 'email',
          to: [this.to().trim()],
          subject: this.subject().trim(),
          body: this.body(),
        })
      : this.api.post<unknown>('/api/v1/note', {
          entity_name: this.entity(),
          record_id: this.recordId(),
          title: this.subject().trim() || this.lang.translate('composer.noteDefaultTitle'),
          note_text: this.body(),
        });
    request.subscribe({
      next: () => {
        this.sending.set(false);
        this.body.set('');
        this.subject.set('');
        this.notice.set(this.lang.translate(channel === 'email' ? 'composer.sent' : 'composer.saved'));
        this.sent.emit(channel);
      },
      error: () => {
        this.sending.set(false);
        this.notice.set(this.lang.translate('composer.failed'));
      },
    });
  }
}
