import { Injectable, inject } from '@angular/core';
import { ApiService, Page } from '@attome/base';
import { Observable, map } from 'rxjs';

/** A record as the portal returns it (`PortalRecord`): only the fields the
 * portal role may read are in `data`. */
export interface PortalRecord<T> {
  id: string;
  row_version: number;
  created_at?: string | null;
  updated_at?: string | null;
  data: T;
}

export type ModerationStatus = 'published' | 'pending' | 'approved' | 'rejected';

export interface ForumCategory {
  name?: string | null;
  name_ar?: string | null;
  description?: string | null;
  sort_order?: number | null;
  is_portal_visible?: boolean | null;
}

export interface ForumThread {
  title?: string | null;
  category_ref?: string | null;
  body?: string | null;
  status?: 'open' | 'answered' | 'closed' | null;
  is_pinned?: boolean | null;
  view_count?: number | null;
  moderation_status?: ModerationStatus | null;
  author_name?: string | null;
  accepted_post_ref?: string | null;
}

export interface ForumPost {
  thread_ref?: string | null;
  body?: string | null;
  is_staff?: boolean | null;
  vote_score?: number | null;
  moderation_status?: ModerationStatus | null;
  author_name?: string | null;
}

export interface ForumIdea {
  title?: string | null;
  category_ref?: string | null;
  description?: string | null;
  status?: 'new' | 'under_review' | 'planned' | 'in_progress' | 'done' | 'declined' | null;
  vote_count?: number | null;
  staff_response?: string | null;
  moderation_status?: ModerationStatus | null;
  author_name?: string | null;
}

/** The portal's own page-size cap (`page_size_cap`, 100 at most). */
const PAGE = 100;

/**
 * G13-T2: the community pack's entities through one portal's record API
 * (`/{keyword}/api/v1/records/{entity}`), under the portal user's session
 * and role plan: what a portal user may read, create and set is the
 * portal's decision, so a write sends only the content fields and the
 * server stamps the rest (owner, moderation by the pack's rules).
 */
@Injectable({ providedIn: 'root' })
export class ForumService {
  private readonly api = inject(ApiService);

  private base(keyword: string, entity: string): string {
    return `/${encodeURIComponent(keyword)}/api/v1/records/${entity}`;
  }

  private list<T>(keyword: string, entity: string, filters: Record<string, string> = {}): Observable<PortalRecord<T>[]> {
    return this.api
      .get<Page<PortalRecord<T>>>(this.base(keyword, entity), { page: '1', page_size: String(PAGE), ...filters })
      .pipe(map(page => page.items));
  }

  categories(keyword: string): Observable<PortalRecord<ForumCategory>[]> {
    return this.list<ForumCategory>(keyword, 'forum_category');
  }

  threads(keyword: string, category: string): Observable<PortalRecord<ForumThread>[]> {
    return this.list<ForumThread>(keyword, 'forum_thread', { category_ref: category });
  }

  thread(keyword: string, id: string): Observable<PortalRecord<ForumThread>> {
    return this.api.get<PortalRecord<ForumThread>>(`${this.base(keyword, 'forum_thread')}/${encodeURIComponent(id)}`);
  }

  posts(keyword: string, thread: string): Observable<PortalRecord<ForumPost>[]> {
    return this.list<ForumPost>(keyword, 'forum_post', { thread_ref: thread });
  }

  ideas(keyword: string, category: string): Observable<PortalRecord<ForumIdea>[]> {
    return this.list<ForumIdea>(keyword, 'forum_idea', { category_ref: category });
  }

  createThread(keyword: string, category: string, title: string, body: string): Observable<PortalRecord<ForumThread>> {
    return this.api.post(this.base(keyword, 'forum_thread'), { category_ref: category, title, body });
  }

  reply(keyword: string, thread: string, body: string): Observable<PortalRecord<ForumPost>> {
    return this.api.post(this.base(keyword, 'forum_post'), { thread_ref: thread, body });
  }

  createIdea(keyword: string, category: string, title: string, description: string): Observable<PortalRecord<ForumIdea>> {
    return this.api.post(this.base(keyword, 'forum_idea'), { category_ref: category, title, description });
  }

  /** One vote by the signed-in portal user: `+1` on an idea, or `+1`/`-1` on a post. */
  vote(keyword: string, target: { idea?: string; post?: string }, voter: string, value: 1 | -1): Observable<unknown> {
    const body: Record<string, unknown> = { voter_key: voter, value };
    if (target.idea) body['idea_ref'] = target.idea;
    if (target.post) body['post_ref'] = target.post;
    return this.api.post(this.base(keyword, 'forum_vote'), body);
  }

  /** The signed-in portal user (`GET /{keyword}/api/v1/me`). */
  me(keyword: string): Observable<{ id: string }> {
    return this.api.get<{ id: string }>(`/${encodeURIComponent(keyword)}/api/v1/me`);
  }
}
