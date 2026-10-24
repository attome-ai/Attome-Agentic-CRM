import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { Observable, catchError, of } from 'rxjs';

import {
  ForumCategory, ForumIdea, ForumPost, ForumService, ForumThread, ModerationStatus, PortalRecord,
} from './forum.service';

/** Rejected items are never shown; the rest in a stable order. Pure. */
export function visibleItems<T extends { moderation_status?: ModerationStatus | null }>(
  items: readonly PortalRecord<T>[],
): PortalRecord<T>[] {
  return items.filter(i => i.data.moderation_status !== 'rejected');
}

type Tab = 'threads' | 'ideas';

/**
 * G13-T2 — `/community/:keyword`: one portal's forum for its signed-in
 * users. Categories (in their order, Arabic names in Arabic), then a
 * category's threads (pinned first) or ideas (most voted first); a thread
 * opens with its posts, the accepted answer first and marked; a user can
 * start a thread, reply, propose an idea and vote. Everything goes through
 * the portal's record API under the user's portal role; what waits for a
 * moderator (a link or a blocked term, the pack's rules) is shown to its
 * author as pending, and rejected items are left out.
 */
@Component({
  selector: 'xrm-portal-forum',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <main class="cf" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" data-testid="forum">
      <h1>{{ 'portalCommunity.title' | translate }}</h1>
      @if (error(); as e) { <p class="cf-error" role="alert" data-testid="forum-error">{{ e }}</p> }
      @if (notice(); as n) { <p class="cf-notice" role="status">{{ n | translate }}</p> }

      @if (signedOut()) {
        <p data-testid="forum-signed-out">{{ 'portalCommunity.signIn' | translate }}</p>
      } @else {
        <div class="cf-layout">
          <nav class="cf-categories" [attr.aria-label]="'portalCommunity.categories' | translate">
            <ul>
              @for (c of categories(); track c.id) {
                <li>
                  <button type="button" class="cf-category" data-testid="forum-category" [attr.data-id]="c.id"
                          [class.cf-category--active]="category() === c.id" [attr.aria-current]="category() === c.id ? 'true' : null"
                          (click)="openCategory(c.id)">
                    {{ categoryName(c) }}
                  </button>
                  @if (c.data.description) { <p class="cf-hint">{{ c.data.description }}</p> }
                </li>
              } @empty {
                <li class="cf-hint">{{ 'portalCommunity.noCategories' | translate }}</li>
              }
            </ul>
          </nav>

          <section class="cf-main" aria-live="polite">
            @if (category()) {
              <div class="cf-tabs" role="tablist">
                <button type="button" role="tab" [attr.aria-selected]="tab() === 'threads'" data-testid="forum-tab-threads"
                        (click)="setTab('threads')">{{ 'portalCommunity.threads' | translate }}</button>
                <button type="button" role="tab" [attr.aria-selected]="tab() === 'ideas'" data-testid="forum-tab-ideas"
                        (click)="setTab('ideas')">{{ 'portalCommunity.ideas' | translate }}</button>
              </div>

              @if (openThread(); as t) {
                <article class="cf-thread" data-testid="forum-thread">
                  <button type="button" class="cf-back" (click)="closeThread()">{{ 'portalCommunity.back' | translate }}</button>
                  <h2>{{ t.data.title }}</h2>
                  <p class="cf-meta">{{ t.data.author_name }} · {{ 'portalCommunity.status.' + (t.data.status || 'open') | translate }}</p>
                  @if (t.data.moderation_status === 'pending') { <p class="cf-pending">{{ 'portalCommunity.pending' | translate }}</p> }
                  <p class="cf-body">{{ t.data.body }}</p>
                  <h3>{{ 'portalCommunity.replies' | translate: { count: posts().length } }}</h3>
                  <ol class="cf-posts">
                    @for (p of posts(); track p.id) {
                      <li class="cf-post" data-testid="forum-post" [attr.data-id]="p.id"
                          [class.cf-post--accepted]="p.id === t.data.accepted_post_ref">
                        @if (p.id === t.data.accepted_post_ref) {
                          <span class="cf-badge" data-testid="forum-accepted">{{ 'portalCommunity.accepted' | translate }}</span>
                        }
                        @if (p.data.is_staff) { <span class="cf-badge">{{ 'portalCommunity.staff' | translate }}</span> }
                        <p class="cf-meta">{{ p.data.author_name }}</p>
                        @if (p.data.moderation_status === 'pending') { <p class="cf-pending">{{ 'portalCommunity.pending' | translate }}</p> }
                        <p class="cf-body">{{ p.data.body }}</p>
                        <div class="cf-votes">
                          <button type="button" [attr.aria-label]="'portalCommunity.voteUp' | translate" (click)="votePost(p, 1)">▲</button>
                          <span dir="ltr">{{ p.data.vote_score ?? 0 }}</span>
                          <button type="button" [attr.aria-label]="'portalCommunity.voteDown' | translate" (click)="votePost(p, -1)">▼</button>
                        </div>
                      </li>
                    }
                  </ol>
                  @if (t.data.status !== 'closed') {
                    <form class="cf-form" (ngSubmit)="reply()">
                      <label for="cf-reply">{{ 'portalCommunity.reply' | translate }}</label>
                      <textarea id="cf-reply" name="reply" rows="4" maxlength="10000" data-testid="forum-reply-body"
                                [ngModel]="replyBody()" (ngModelChange)="replyBody.set($event)"></textarea>
                      <button type="submit" data-testid="forum-reply" [disabled]="busy() || !replyBody().trim()">
                        {{ 'portalCommunity.send' | translate }}
                      </button>
                    </form>
                  } @else {
                    <p class="cf-hint">{{ 'portalCommunity.closed' | translate }}</p>
                  }
                </article>
              } @else if (tab() === 'threads') {
                <ul class="cf-list">
                  @for (t of threads(); track t.id) {
                    <li data-testid="forum-thread-row" [attr.data-id]="t.id">
                      <button type="button" class="cf-link" (click)="openThreadById(t.id)">
                        @if (t.data.is_pinned) { <span class="cf-badge">{{ 'portalCommunity.pinned' | translate }}</span> }
                        {{ t.data.title }}
                      </button>
                      <span class="cf-meta">{{ 'portalCommunity.status.' + (t.data.status || 'open') | translate }}</span>
                      @if (t.data.moderation_status === 'pending') { <span class="cf-pending">{{ 'portalCommunity.pending' | translate }}</span> }
                    </li>
                  } @empty {
                    <li class="cf-hint">{{ 'portalCommunity.noThreads' | translate }}</li>
                  }
                </ul>
                <form class="cf-form" (ngSubmit)="startThread()">
                  <h3>{{ 'portalCommunity.newThread' | translate }}</h3>
                  <label for="cf-title">{{ 'portalCommunity.threadTitle' | translate }}</label>
                  <input id="cf-title" name="title" maxlength="200" data-testid="forum-new-title"
                         [ngModel]="newTitle()" (ngModelChange)="newTitle.set($event)" />
                  <label for="cf-body">{{ 'portalCommunity.threadBody' | translate }}</label>
                  <textarea id="cf-body" name="body" rows="5" maxlength="10000" data-testid="forum-new-body"
                            [ngModel]="newBody()" (ngModelChange)="newBody.set($event)"></textarea>
                  <button type="submit" data-testid="forum-new-thread" [disabled]="busy() || !newTitle().trim() || !newBody().trim()">
                    {{ 'portalCommunity.post' | translate }}
                  </button>
                </form>
              } @else {
                <ul class="cf-list">
                  @for (i of ideas(); track i.id) {
                    <li data-testid="forum-idea" [attr.data-id]="i.id">
                      <div class="cf-votes">
                        <button type="button" data-testid="forum-vote-idea" [attr.aria-label]="'portalCommunity.voteIdea' | translate"
                                [disabled]="voted().has(i.id)" (click)="voteIdea(i)">▲</button>
                        <span dir="ltr">{{ i.data.vote_count ?? 0 }}</span>
                      </div>
                      <div>
                        <strong>{{ i.data.title }}</strong>
                        <span class="cf-badge">{{ 'portalCommunity.ideaStatus.' + (i.data.status || 'new') | translate }}</span>
                        @if (i.data.moderation_status === 'pending') { <span class="cf-pending">{{ 'portalCommunity.pending' | translate }}</span> }
                        @if (i.data.description) { <p class="cf-body">{{ i.data.description }}</p> }
                        @if (i.data.staff_response) {
                          <p class="cf-response"><span class="cf-badge">{{ 'portalCommunity.staff' | translate }}</span> {{ i.data.staff_response }}</p>
                        }
                      </div>
                    </li>
                  } @empty {
                    <li class="cf-hint">{{ 'portalCommunity.noIdeas' | translate }}</li>
                  }
                </ul>
                <form class="cf-form" (ngSubmit)="proposeIdea()">
                  <h3>{{ 'portalCommunity.newIdea' | translate }}</h3>
                  <label for="cf-idea-title">{{ 'portalCommunity.ideaTitle' | translate }}</label>
                  <input id="cf-idea-title" name="ideaTitle" maxlength="200" data-testid="forum-idea-title"
                         [ngModel]="newTitle()" (ngModelChange)="newTitle.set($event)" />
                  <label for="cf-idea-body">{{ 'portalCommunity.ideaBody' | translate }}</label>
                  <textarea id="cf-idea-body" name="ideaBody" rows="4" maxlength="10000"
                            [ngModel]="newBody()" (ngModelChange)="newBody.set($event)"></textarea>
                  <button type="submit" data-testid="forum-new-idea" [disabled]="busy() || !newTitle().trim()">
                    {{ 'portalCommunity.propose' | translate }}
                  </button>
                </form>
              }
            } @else {
              <p class="cf-hint">{{ 'portalCommunity.pickCategory' | translate }}</p>
            }
          </section>
        </div>
      }
    </main>
  `,
  styles: [`
    .cf { max-inline-size: 72rem; margin-inline: auto; padding: var(--space-4, 1rem); display: grid; gap: var(--space-3, .75rem); }
    .cf-layout { display: grid; grid-template-columns: minmax(12rem, 16rem) minmax(0, 1fr); gap: var(--space-4, 1rem); }
    @media (max-width: 48rem) { .cf-layout { grid-template-columns: minmax(0, 1fr); } }
    .cf-categories ul, .cf-list, .cf-posts { list-style: none; margin: 0; padding: 0; display: grid; gap: .5rem; }
    .cf-category, .cf-link { background: none; border: none; padding: 0; color: var(--color-primary, #2b6cb0); cursor: pointer; text-align: start; font: inherit; }
    .cf-category--active { font-weight: 700; }
    .cf-tabs { display: flex; gap: .5rem; border-block-end: 1px solid var(--color-border, #ddd); padding-block-end: .5rem; }
    .cf-tabs [aria-selected='true'] { font-weight: 700; }
    .cf-list li { display: flex; flex-wrap: wrap; align-items: baseline; gap: .25rem .75rem; padding-block: .5rem; border-block-end: 1px solid var(--color-border, #eee); }
    .cf-post { padding: .75rem; border: 1px solid var(--color-border, #ddd); border-radius: 6px; }
    .cf-post--accepted { border-color: var(--color-success, #2f855a); border-inline-start-width: 4px; }
    .cf-badge { display: inline-block; font-size: .75rem; padding-inline: .375rem; border-radius: 999px; background: var(--color-bg-alt, #f0f0f0); margin-inline-end: .25rem; }
    .cf-meta, .cf-hint { color: var(--color-text-secondary, #666); font-size: .875rem; margin: 0; }
    .cf-pending { color: var(--color-warning, #8a5a00); font-size: .875rem; margin: 0; }
    .cf-body { white-space: pre-line; margin: .25rem 0; }
    .cf-votes { display: inline-flex; align-items: center; gap: .25rem; }
    .cf-form { display: grid; gap: .375rem; max-inline-size: 40rem; margin-block-start: var(--space-3, .75rem); }
    .cf-error { color: var(--color-danger, #c53030); }
    .cf-back { justify-self: start; }
  `],
})
export class ForumComponent {
  private readonly svc = inject(ForumService);
  protected readonly lang = inject(LangService);

  /** The portal's keyword (route parameter). */
  readonly keyword = input.required<string>();

  protected readonly categoryRows = signal<PortalRecord<ForumCategory>[]>([]);
  protected readonly category = signal<string | null>(null);
  protected readonly tab = signal<Tab>('threads');
  private readonly threadRows = signal<PortalRecord<ForumThread>[]>([]);
  private readonly ideaRows = signal<PortalRecord<ForumIdea>[]>([]);
  private readonly postRows = signal<PortalRecord<ForumPost>[]>([]);
  protected readonly openThread = signal<PortalRecord<ForumThread> | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly signedOut = signal(false);
  protected readonly busy = signal(false);
  protected readonly voted = signal<Set<string>>(new Set());
  protected readonly newTitle = signal('');
  protected readonly newBody = signal('');
  protected readonly replyBody = signal('');
  private me: string | null = null;

  /** Visible categories in their order. */
  protected readonly categories = computed(() =>
    this.categoryRows()
      .filter(c => c.data.is_portal_visible !== false)
      .sort((a, b) => (a.data.sort_order ?? 0) - (b.data.sort_order ?? 0)),
  );
  /** Pinned first, then newest. */
  protected readonly threads = computed(() =>
    visibleItems(this.threadRows()).sort((a, b) =>
      Number(!!b.data.is_pinned) - Number(!!a.data.is_pinned) || (b.created_at ?? '').localeCompare(a.created_at ?? '')),
  );
  /** Most voted first. */
  protected readonly ideas = computed(() =>
    visibleItems(this.ideaRows()).sort((a, b) => (b.data.vote_count ?? 0) - (a.data.vote_count ?? 0)),
  );
  /** The accepted answer first, then in the order they were written. */
  protected readonly posts = computed(() => {
    const accepted = this.openThread()?.data.accepted_post_ref;
    return visibleItems(this.postRows()).sort((a, b) =>
      Number(b.id === accepted) - Number(a.id === accepted) || (a.created_at ?? '').localeCompare(b.created_at ?? ''));
  });

  constructor() {
    effect(() => {
      const keyword = this.keyword();
      untracked(() => this.loadCategories(keyword));
    });
  }

  protected categoryName(c: PortalRecord<ForumCategory>): string {
    return (this.lang.isRtl() && c.data.name_ar) || c.data.name || '';
  }

  protected openCategory(id: string): void {
    this.category.set(id);
    this.openThread.set(null);
    this.load();
  }

  protected setTab(tab: Tab): void {
    this.tab.set(tab);
    this.openThread.set(null);
    this.newTitle.set('');
    this.newBody.set('');
    this.load();
  }

  protected openThreadById(id: string): void {
    this.guard(this.svc.thread(this.keyword(), id)).subscribe(t => {
      if (!t) return;
      this.openThread.set(t);
      this.replyBody.set('');
      this.loadPosts(t.id);
    });
  }

  protected closeThread(): void {
    this.openThread.set(null);
    this.load();
  }

  protected startThread(): void {
    const category = this.category();
    if (!category) return;
    this.write(this.svc.createThread(this.keyword(), category, this.newTitle().trim(), this.newBody().trim()), () => {
      this.newTitle.set('');
      this.newBody.set('');
      this.load();
    });
  }

  protected reply(): void {
    const thread = this.openThread();
    if (!thread) return;
    this.write(this.svc.reply(this.keyword(), thread.id, this.replyBody().trim()), () => {
      this.replyBody.set('');
      this.loadPosts(thread.id);
    });
  }

  protected proposeIdea(): void {
    const category = this.category();
    if (!category) return;
    this.write(this.svc.createIdea(this.keyword(), category, this.newTitle().trim(), this.newBody().trim()), () => {
      this.newTitle.set('');
      this.newBody.set('');
      this.load();
    });
  }

  protected voteIdea(idea: PortalRecord<ForumIdea>): void {
    this.withMe(me => this.write(this.svc.vote(this.keyword(), { idea: idea.id }, me, 1), () => {
      this.voted.update(s => new Set(s).add(idea.id));
      this.load();
    }, false));
  }

  protected votePost(post: PortalRecord<ForumPost>, value: 1 | -1): void {
    const thread = this.openThread();
    this.withMe(me => this.write(this.svc.vote(this.keyword(), { post: post.id }, me, value), () => {
      if (thread) this.loadPosts(thread.id);
    }, false));
  }

  /** The portal user's id, read once, as the vote's voter. */
  private withMe(then: (me: string) => void): void {
    if (this.me) {
      then(this.me);
      return;
    }
    this.guard(this.svc.me(this.keyword())).subscribe(me => {
      if (!me) return;
      this.me = me.id;
      then(me.id);
    });
  }

  private write<T>(call: Observable<T>, then: () => void, announce = true): void {
    this.busy.set(true);
    this.notice.set(null);
    this.guard(call).subscribe(result => {
      this.busy.set(false);
      if (result === null) return;
      if (announce) this.notice.set('portalCommunity.posted');
      then();
    });
  }

  private load(): void {
    const category = this.category();
    if (!category) return;
    if (this.tab() === 'threads') {
      this.guard(this.svc.threads(this.keyword(), category)).subscribe(rows => { if (rows) this.threadRows.set(rows); });
    } else {
      this.guard(this.svc.ideas(this.keyword(), category)).subscribe(rows => { if (rows) this.ideaRows.set(rows); });
    }
  }

  private loadPosts(thread: string): void {
    this.guard(this.svc.posts(this.keyword(), thread)).subscribe(rows => { if (rows) this.postRows.set(rows); });
  }

  private loadCategories(keyword: string): void {
    this.guard(this.svc.categories(keyword)).subscribe(rows => {
      if (!rows) return;
      this.categoryRows.set(rows);
      const first = this.categories()[0];
      if (first && !this.category()) this.openCategory(first.id);
    });
  }

  /** Errors become a message; a missing portal session asks the user to sign in. */
  private guard<T>(call: Observable<T>): Observable<T | null> {
    return call.pipe(
      catchError((e: unknown) => {
        this.busy.set(false);
        if ((e as ApiError).status === 401) this.signedOut.set(true);
        else this.error.set(this.lang.errorText(e as ApiError));
        return of(null);
      }),
    );
  }
}
