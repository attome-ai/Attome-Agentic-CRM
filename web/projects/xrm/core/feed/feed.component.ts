import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiService, AuthService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

export type FeedKind = 'post' | 'record_event';

/** One feed item (`GET /api/v1/feed`). */
export interface FeedItem {
  kind: FeedKind;
  id: string;
  occurred_at: string;
  actor: string | null;
  body: string | null;
  entity: string | null;
  record_id: string | null;
  operation: string | null;
  record_name: string | null;
}

export interface FeedPage {
  items: FeedItem[];
  next_cursor?: string | null;
}

/** Longest post the server keeps (`feed_post.body`). */
const MAX_POST = 4000;
const PAGE_SIZE = '25';

/** The catalog key that describes a record event. Pure. */
export function feedEventKey(operation: string | null): string {
  switch (operation) {
    case 'create': return 'feed.event.create';
    case 'delete': return 'feed.event.delete';
    case 'restore': return 'feed.event.restore';
    default: return 'feed.event.update';
  }
}

/**
 * C3-T2: the signed-in person's feed — colleagues' posts and changes to the
 * records they follow (C3-T1), newest first, with a filter by kind and a
 * composer. The server decides what the person may see; a record they can
 * no longer read never appears. Older items load on demand (keyset).
 */
@Component({
  selector: 'xrm-feed',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, LocalDatePipe, RouterLink],
  template: `
    <section class="fd" [attr.aria-label]="'feed.title' | translate">
      <h1 class="fd-title">{{ 'feed.title' | translate }}</h1>

      <form class="fd-compose" (submit)="post($event)">
        <label class="fd-label" for="xrm-feed-compose">{{ 'feed.composeLabel' | translate }}</label>
        <textarea id="xrm-feed-compose" rows="3" [maxLength]="maxPost" [value]="draft()"
                  (input)="draft.set($any($event.target).value)"
                  [placeholder]="'feed.composePlaceholder' | translate" data-testid="feed-draft"></textarea>
        <div class="fd-row">
          @if (postError(); as message) {
            <span class="fd-error" role="alert" data-testid="feed-post-error">{{ message }}</span>
          }
          <button type="submit" class="fd-btn" [disabled]="posting() || !draft().trim()" data-testid="feed-post">
            {{ (posting() ? 'feed.posting' : 'feed.post') | translate }}
          </button>
        </div>
      </form>

      <div class="fd-filters" role="group" [attr.aria-label]="'feed.filterLabel' | translate">
        @for (f of filters; track f.value) {
          <button type="button" class="fd-chip" [class.fd-chip-on]="kind() === f.value"
                  [attr.aria-pressed]="kind() === f.value" (click)="setKind(f.value)"
                  [attr.data-testid]="'feed-filter-' + (f.value ?? 'all')">
            {{ f.label | translate }}
          </button>
        }
      </div>

      @if (error()) {
        <p class="fd-error" role="alert" data-testid="feed-error">{{ 'feed.loadFailed' | translate }}</p>
      }
      <ul class="fd-list">
        @for (item of items(); track item.kind + item.id) {
          <li class="fd-item" [class.fd-event]="item.kind === 'record_event'" data-testid="feed-item">
            <div class="fd-meta">
              <span>{{ (item.actor && item.actor === me ? 'feed.you' : 'feed.colleague') | translate }}</span>
              <time [attr.datetime]="item.occurred_at">{{ item.occurred_at | localDate: { dateStyle: 'medium', timeStyle: 'short' } }}</time>
            </div>
            @if (item.kind === 'post') {
              <p class="fd-body">{{ item.body }}</p>
            } @else {
              <p class="fd-body">
                {{ eventKey(item.operation) | translate }}
                <a [routerLink]="['/xrm/entity', item.entity, 'form']" [queryParams]="{ id: item.record_id }">
                  {{ item.record_name || item.entity }}
                </a>
              </p>
            }
          </li>
        } @empty {
          @if (!loading()) {
            <li class="fd-empty" data-testid="feed-empty">{{ 'feed.empty' | translate }}</li>
          }
        }
      </ul>
      @if (loading()) {
        <p role="status">{{ 'feed.loading' | translate }}</p>
      } @else if (nextCursor()) {
        <button type="button" class="fd-btn fd-more" (click)="more()" data-testid="feed-more">
          {{ 'feed.more' | translate }}
        </button>
      }
    </section>
  `,
  styles: [`
    .fd { max-inline-size: 760px; margin-inline: auto; padding-block: 24px; padding-inline: 16px; display: grid; gap: 16px; }
    .fd-title { margin: 0; font-size: 22px; }
    .fd-compose { display: grid; gap: 8px; }
    .fd-label { font-weight: 600; }
    .fd-compose textarea { inline-size: 100%; resize: vertical; padding-block: 8px; padding-inline: 10px;
                           border: 1px solid var(--color-border); border-radius: 8px;
                           background: var(--color-bg); color: var(--color-text-primary); font: inherit; }
    .fd-row { display: flex; align-items: center; justify-content: flex-end; gap: 12px; }
    .fd-btn { padding-block: 8px; padding-inline: 16px; border: none; border-radius: 8px; cursor: pointer;
              background: var(--color-accent); color: var(--color-bg); font-weight: 700; }
    .fd-btn:disabled { opacity: .5; cursor: not-allowed; }
    .fd-filters { display: flex; flex-wrap: wrap; gap: 8px; }
    .fd-chip { padding-block: 4px; padding-inline: 12px; border-radius: 999px; cursor: pointer;
               border: 1px solid var(--color-border); background: var(--color-bg-alt); color: var(--color-text-primary); }
    .fd-chip-on { border-color: var(--color-accent); color: var(--color-accent); }
    .fd-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 12px; }
    .fd-item { border: 1px solid var(--color-border); border-radius: 8px; padding-block: 12px; padding-inline: 14px; display: grid; gap: 6px; }
    .fd-event { background: var(--color-bg-alt); }
    .fd-meta { display: flex; justify-content: space-between; gap: 8px; font-size: 12px; color: var(--color-text-secondary); }
    .fd-body { margin: 0; white-space: pre-wrap; }
    .fd-empty { color: var(--color-text-secondary); }
    .fd-error { color: var(--color-error); }
    .fd-more { justify-self: center; }
  `],
})
export class FeedComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  readonly me = inject(AuthService).userId();

  readonly maxPost = MAX_POST;
  readonly filters: { value: FeedKind | null; label: string }[] = [
    { value: null, label: 'feed.filter.all' },
    { value: 'post', label: 'feed.filter.posts' },
    { value: 'record_event', label: 'feed.filter.records' },
  ];

  readonly items = signal<FeedItem[]>([]);
  readonly nextCursor = signal<string | null>(null);
  readonly kind = signal<FeedKind | null>(null);
  readonly loading = signal(false);
  readonly error = signal(false);
  readonly draft = signal('');
  readonly posting = signal(false);
  readonly postError = signal<string | null>(null);

  readonly eventKey = feedEventKey;

  ngOnInit(): void {
    this.load(null);
  }

  setKind(kind: FeedKind | null): void {
    if (kind === this.kind()) return;
    this.kind.set(kind);
    this.items.set([]);
    this.load(null);
  }

  more(): void {
    const cursor = this.nextCursor();
    if (cursor) this.load(cursor);
  }

  post(event: Event): void {
    event.preventDefault();
    const body = this.draft().trim().slice(0, MAX_POST);
    if (!body || this.posting()) return;
    this.posting.set(true);
    this.postError.set(null);
    this.api.post<unknown>('/api/v1/feed_post', { body }).subscribe({
      next: () => {
        this.posting.set(false);
        this.draft.set('');
        this.items.set([]);
        this.load(null);
      },
      error: (e: { kind?: string }) => {
        this.posting.set(false);
        this.postError.set(this.lang.translate(
          e?.kind === 'forbidden' ? 'feed.postForbidden' : 'feed.postFailed',
        ));
      },
    });
  }

  private load(cursor: string | null): void {
    const params: Record<string, string> = { page_size: PAGE_SIZE };
    if (cursor) params['cursor'] = cursor;
    const kind = this.kind();
    if (kind) params['kind'] = kind;
    this.loading.set(true);
    this.error.set(false);
    this.api.get<FeedPage>('/api/v1/feed', params).subscribe({
      next: page => {
        this.items.update(items => (cursor ? [...items, ...page.items] : page.items));
        this.nextCursor.set(page.next_cursor ?? null);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
        this.error.set(true);
      },
    });
  }
}
