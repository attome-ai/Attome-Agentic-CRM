import {
  ChangeDetectionStrategy, Component, OnInit, computed, inject, signal,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Observable, catchError, forkJoin, map, of } from 'rxjs';
import {
  ApiService, AuthService, LangService, LocalDatePipe, MentionCandidate, MentionPickerComponent,
  MentionSearch, TranslatePipe,
} from '@attome/base';

/** A channel as its member sees it (`GET /api/v1/chat/channels`). */
export interface ChatChannel {
  id: string;
  kind: 'direct' | 'group' | 'record';
  name: string | null;
  entity_name: string | null;
  record_id: string | null;
  retention_days: number | null;
  role: 'owner' | 'member';
  members: string[];
  last_message_at: string | null;
  unread: number;
}

/** One message (`GET /api/v1/chat/channels/{id}/messages`). */
export interface ChatMessage {
  id: string;
  channel_id: string;
  thread_root_id: string | null;
  author_id: string;
  body: string;
  file_id: string | null;
  created_at: string;
  deleted: boolean;
  reply_count: number;
}

/** A piece of a message: text, a person or team, or a record card. */
export type MessagePart =
  | { kind: 'text'; text: string }
  | { kind: 'mention'; target: 'user' | 'team'; id: string }
  | { kind: 'record'; entity: string; id: string };

interface Page<T> { items: T[]; next_cursor?: string | null }

/**
 * A message body split into text, mentions (`@[user:id]`, `@[team:id]`) and
 * record cards (`@[record:entity/id]`); anything malformed stays text. Pure.
 */
export function messageParts(body: string): MessagePart[] {
  const out: MessagePart[] = [];
  const re = /@\[(user|team|record):([^\]]+)\]/g;
  let last = 0;
  for (let m = re.exec(body); m; m = re.exec(body)) {
    const [whole, kind, ref] = m;
    let part: MessagePart | null = null;
    if (kind === 'record') {
      const slash = ref.indexOf('/');
      if (slash > 0) part = { kind: 'record', entity: ref.slice(0, slash), id: ref.slice(slash + 1) };
    } else {
      part = { kind: 'mention', target: kind as 'user' | 'team', id: ref };
    }
    if (!part) continue;
    if (m.index > last) out.push({ kind: 'text', text: body.slice(last, m.index) });
    out.push(part);
    last = m.index + whole.length;
  }
  if (last < body.length) out.push({ kind: 'text', text: body.slice(last) });
  return out;
}

const MAX_BODY = 8000;

/**
 * C9-T2: internal chat. The person's channels (unread first by activity),
 * one channel's messages with record cards and mentions, a composer with the
 * mention picker, and — in a record channel — "save to record", which keeps
 * a message as a note on that record. Membership is the server's: a channel
 * the person is not in never appears.
 */
@Component({
  selector: 'xrm-chat',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, LocalDatePipe, RouterLink, MentionPickerComponent],
  template: `
    <section class="ch" [attr.aria-label]="'chat.title' | translate">
      <aside class="ch-side">
        <h1 class="ch-title">{{ 'chat.title' | translate }}</h1>
        <form class="ch-new" (submit)="createGroup($event)">
          <input type="text" [value]="newName()" (input)="newName.set($any($event.target).value)"
                 [placeholder]="'chat.newGroupPlaceholder' | translate"
                 [attr.aria-label]="'chat.newGroup' | translate" data-testid="chat-new-name" />
          <button type="submit" class="ch-btn" [disabled]="!newName().trim()" data-testid="chat-new">
            {{ 'chat.newGroup' | translate }}
          </button>
        </form>
        <ul class="ch-channels">
          @for (c of channels(); track c.id) {
            <li>
              <button type="button" class="ch-channel" [class.ch-on]="c.id === selectedId()"
                      (click)="open(c)" data-testid="chat-channel">
                <span>{{ channelName(c) }}</span>
                @if (c.unread > 0) {
                  <span class="ch-unread" [attr.aria-label]="'chat.unread' | translate">{{ c.unread }}</span>
                }
              </button>
            </li>
          } @empty {
            <li class="ch-note" data-testid="chat-no-channels">{{ 'chat.noChannels' | translate }}</li>
          }
        </ul>
      </aside>

      <div class="ch-main">
        @if (selected(); as channel) {
          <header class="ch-head">
            <h2>{{ channelName(channel) }}</h2>
            @if (channel.kind === 'record') {
              <a [routerLink]="['/xrm/entity', channel.entity_name, 'form']" [queryParams]="{ id: channel.record_id }">
                {{ 'chat.openRecord' | translate }}
              </a>
            }
          </header>
          @if (notice(); as message) {
            <p class="ch-note" role="status" data-testid="chat-notice">{{ message }}</p>
          }
          <ol class="ch-messages" data-testid="chat-messages">
            @for (m of messages(); track m.id) {
              <li class="ch-message" [class.ch-mine]="m.author_id === me" data-testid="chat-message">
                <div class="ch-meta">
                  <span>{{ (m.author_id === me ? 'chat.you' : 'chat.colleague') | translate }}</span>
                  <time [attr.datetime]="m.created_at">{{ m.created_at | localDate: { timeStyle: 'short', dateStyle: 'short' } }}</time>
                </div>
                @if (m.deleted) {
                  <p class="ch-deleted">{{ 'chat.deleted' | translate }}</p>
                } @else {
                  <p class="ch-body">
                    @for (p of parts(m.body); track $index) {
                      @switch (p.kind) {
                        @case ('text') { <span>{{ p.text }}</span> }
                        @case ('mention') { <span class="ch-mention">{{ ('chat.mention.' + p.target) | translate }}</span> }
                        @case ('record') {
                          <a class="ch-card" [routerLink]="['/xrm/entity', p.entity, 'form']" [queryParams]="{ id: p.id }"
                             data-testid="chat-record-card">
                            <i class="las la-link" aria-hidden="true"></i> {{ p.entity }}
                          </a>
                        }
                      }
                    }
                  </p>
                  @if (m.file_id) {
                    <a class="ch-card" [routerLink]="['/xrm/entity', 'attome_document', 'form']"
                       [queryParams]="{ id: m.file_id }" data-testid="chat-file">
                      <i class="las la-paperclip" aria-hidden="true"></i> {{ 'chat.attachment' | translate }}
                    </a>
                  }
                  @if (channel.kind === 'record') {
                    <button type="button" class="ch-link" (click)="saveToRecord(channel, m)"
                            data-testid="chat-save">{{ 'chat.saveToRecord' | translate }}</button>
                  }
                }
              </li>
            } @empty {
              <li class="ch-note">{{ 'chat.noMessages' | translate }}</li>
            }
          </ol>
          <form class="ch-compose" (submit)="send($event)">
            <textarea #box rows="2" [maxLength]="maxBody" [value]="draft()"
                      (input)="draft.set($any($event.target).value)"
                      (keydown.enter)="onEnter($any($event), box)"
                      [placeholder]="'chat.composePlaceholder' | translate"
                      [attr.aria-label]="'chat.compose' | translate" data-testid="chat-draft"></textarea>
            <base-mention-picker [target]="box" [search]="mentionSearch" />
            <button type="submit" class="ch-btn" [disabled]="sending() || !draft().trim()" data-testid="chat-send">
              {{ 'chat.send' | translate }}
            </button>
          </form>
        } @else {
          <p class="ch-note">{{ 'chat.pick' | translate }}</p>
        }
        @if (error(); as message) {
          <p class="ch-error" role="alert" data-testid="chat-error">{{ message }}</p>
        }
      </div>
    </section>
  `,
  styles: [`
    .ch { display: grid; grid-template-columns: minmax(200px, 280px) 1fr; gap: 16px; padding-block: 16px; padding-inline: 16px; }
    @media (max-width: 720px) { .ch { grid-template-columns: 1fr; } }
    .ch-title { margin: 0; font-size: 20px; }
    .ch-side { display: grid; gap: 12px; align-content: start; }
    .ch-new { display: flex; gap: 6px; }
    .ch-new input { flex: 1; min-inline-size: 0; padding-block: 6px; padding-inline: 8px;
                    border: 1px solid var(--color-border); border-radius: 6px; background: var(--color-bg); color: var(--color-text-primary); }
    .ch-channels, .ch-messages { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
    .ch-channel { inline-size: 100%; display: flex; justify-content: space-between; gap: 8px; text-align: start;
                  padding-block: 8px; padding-inline: 10px; border: 1px solid var(--color-border); border-radius: 8px;
                  background: var(--color-bg); color: var(--color-text-primary); cursor: pointer; }
    .ch-on { border-color: var(--color-accent); }
    .ch-unread { min-inline-size: 20px; text-align: center; border-radius: 999px; padding-inline: 6px;
                 background: var(--color-accent); color: var(--color-bg); font-size: 12px; }
    .ch-main { display: grid; gap: 12px; align-content: start; }
    .ch-head { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
    .ch-head h2 { margin: 0; font-size: 18px; }
    .ch-message { border: 1px solid var(--color-border); border-radius: 8px; padding-block: 8px; padding-inline: 12px; display: grid; gap: 4px; }
    .ch-mine { background: var(--color-bg-alt); }
    .ch-meta { display: flex; justify-content: space-between; font-size: 12px; color: var(--color-text-secondary); }
    .ch-body { margin: 0; white-space: pre-wrap; }
    .ch-mention { font-weight: 600; color: var(--color-accent); }
    .ch-card { display: inline-flex; align-items: center; gap: 4px; padding-block: 2px; padding-inline: 8px;
               border: 1px solid var(--color-border); border-radius: 6px; }
    .ch-deleted, .ch-note { color: var(--color-text-secondary); }
    .ch-link { justify-self: start; background: none; border: none; color: var(--color-accent); cursor: pointer; padding: 0; }
    .ch-compose { display: grid; gap: 6px; }
    .ch-compose textarea { inline-size: 100%; resize: vertical; padding-block: 8px; padding-inline: 10px;
                           border: 1px solid var(--color-border); border-radius: 8px; background: var(--color-bg);
                           color: var(--color-text-primary); font: inherit; }
    .ch-btn { justify-self: end; padding-block: 6px; padding-inline: 14px; border: none; border-radius: 8px;
              background: var(--color-accent); color: var(--color-bg); font-weight: 700; cursor: pointer; }
    .ch-btn:disabled { opacity: .5; cursor: not-allowed; }
    .ch-error { color: var(--color-error); }
  `],
})
export class ChatComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  readonly me = inject(AuthService).userId();

  readonly maxBody = MAX_BODY;
  readonly channels = signal<ChatChannel[]>([]);
  readonly selectedId = signal<string | null>(null);
  readonly selected = computed(() => this.channels().find(c => c.id === this.selectedId()) ?? null);
  readonly messages = signal<ChatMessage[]>([]);
  readonly draft = signal('');
  readonly newName = signal('');
  readonly sending = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);

  readonly parts = messageParts;

  /** People and teams by lookup, records by global search; each fails to nothing. */
  readonly mentionSearch: MentionSearch = (query: string) => {
    const term = query.trim();
    const none = of([] as MentionCandidate[]);
    const lookup = (entity: string, field: string, kind: 'user' | 'team'): Observable<MentionCandidate[]> =>
      this.api.post<{ data: { records: Record<string, unknown>[] } }>('/api/v1/query/execute', {
        entity,
        page_size: 5,
        filters: term ? [{ field, op: 'contains', value: term }] : [],
      }).pipe(
        map(res => res.data.records.map(r => ({
          kind, id: String(r['id']), label: String(r[field] || r['email'] || r['id']),
        }))),
        catchError(() => none),
      );
    const records: Observable<MentionCandidate[]> = term.length < 2 ? none
      : this.api.get<{ items: { entity_logicalname: string; record_id: string; title?: string | null }[] }>(
          '/api/v1/search', { q: term, page_size: '5' },
        ).pipe(
          map(res => res.items.map(h => ({
            kind: 'record' as const, id: h.record_id, entity: h.entity_logicalname,
            label: h.title || h.record_id, detail: h.entity_logicalname,
          }))),
          catchError(() => none),
        );
    return forkJoin([lookup('user_account', 'user_name', 'user'), lookup('team', 'name', 'team'), records])
      .pipe(map(([p, t, r]) => [...p, ...t, ...r]));
  };

  ngOnInit(): void {
    this.loadChannels();
  }

  channelName(c: ChatChannel): string {
    if (c.name) return c.name;
    if (c.kind === 'direct') return this.lang.translate('chat.direct');
    return c.entity_name ?? this.lang.translate('chat.untitled');
  }

  open(c: ChatChannel): void {
    this.selectedId.set(c.id);
    this.notice.set(null);
    this.error.set(null);
    this.api.get<Page<ChatMessage>>(`/api/v1/chat/channels/${c.id}/messages`, { page_size: '50' }).subscribe({
      // Newest first from the server; oldest first on screen.
      next: page => this.messages.set([...page.items].reverse()),
      error: () => this.error.set(this.lang.translate('chat.loadFailed')),
    });
    if (c.unread > 0) {
      this.api.post<void>(`/api/v1/chat/channels/${c.id}/read`, {}).subscribe({
        next: () => this.channels.update(list => list.map(x => (x.id === c.id ? { ...x, unread: 0 } : x))),
        error: () => undefined,
      });
    }
  }

  onEnter(event: KeyboardEvent, box: HTMLTextAreaElement): void {
    // Shift+Enter is a new line; an open mention list takes Enter itself.
    if (event.shiftKey || box.getAttribute('aria-expanded') === 'true') return;
    this.send(event);
  }

  send(event: Event): void {
    event.preventDefault();
    const channel = this.selected();
    const body = this.draft().trim().slice(0, MAX_BODY);
    if (!channel || !body || this.sending()) return;
    this.sending.set(true);
    this.api.post<ChatMessage>(`/api/v1/chat/channels/${channel.id}/messages`, { body }).subscribe({
      next: message => {
        this.sending.set(false);
        this.draft.set('');
        this.messages.update(list => [...list, message]);
      },
      error: () => {
        this.sending.set(false);
        this.error.set(this.lang.translate('chat.sendFailed'));
      },
    });
  }

  /** Keeps a message as a note on the channel's record. */
  saveToRecord(channel: ChatChannel, message: ChatMessage): void {
    if (channel.kind !== 'record' || !channel.entity_name || !channel.record_id) return;
    this.api.post<unknown>('/api/v1/note', {
      entity_name: channel.entity_name,
      record_id: channel.record_id,
      title: this.lang.translate('chat.noteTitle'),
      note_text: message.body,
    }).subscribe({
      next: () => this.notice.set(this.lang.translate('chat.saved')),
      error: () => this.error.set(this.lang.translate('chat.saveFailed')),
    });
  }

  createGroup(event: Event): void {
    event.preventDefault();
    const name = this.newName().trim();
    if (!name) return;
    this.api.post<ChatChannel>('/api/v1/chat/channels', { kind: 'group', name, members: [] }).subscribe({
      next: channel => {
        this.newName.set('');
        this.channels.update(list => [channel, ...list.filter(c => c.id !== channel.id)]);
        this.open(channel);
      },
      error: () => this.error.set(this.lang.translate('chat.createFailed')),
    });
  }

  private loadChannels(): void {
    this.api.get<Page<ChatChannel>>('/api/v1/chat/channels', { page_size: '100' }).subscribe({
      next: page => this.channels.set(page.items),
      error: () => this.error.set(this.lang.translate('chat.loadFailed')),
    });
  }
}
