import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

// ── Wire types (mirror attome-content/src/model.rs exactly) ──────────────────
//
// `Block`/`BlockKind` live here — the smaller, public-facing entry point —
// rather than in the admin entry's `content-admin.service.ts`, so the
// public route (`@attome/xrm/content/view`, loaded on every unmatched URL)
// never pulls in the admin editor's much larger code just to get these two
// shared types. The admin entry re-exports them as types (erased at
// compile time, so this stays a one-directional, zero-runtime-cost split —
// D-185's reasoning, applied one level deeper).

/** The full block library — keep in sync with `attome_content::model::BlockKind`. */
export type BlockKind =
  | 'heading'
  | 'rich_text'
  | 'alert'
  | 'image'
  | 'columns'
  | 'data_table'
  | 'chart'
  | 'form'
  | 'component';

export interface Block {
  id:    string;
  kind:  BlockKind;
  props: Record<string, unknown>;
}

export interface PublicPageView {
  title:            string;
  blocks:           Block[];
  seo_title:        string | null;
  seo_description:  string | null;
}

/** M37 Phase 2 (D-452). */
export interface VoteAck {
  recorded: boolean;
}

/**
 * The public, anonymous page-view client — deliberately separate from
 * `ContentAdminService` (which always sends credentials and hits
 * `/admin/content/...`): this calls the bypass route
 * (`/api/v1/content/view`) that never requires a session.
 */
@Injectable({ providedIn: 'root' })
export class ContentPublicService {
  private readonly api = inject(ApiService);

  view(path: string): Observable<PublicPageView> {
    return this.api.get<PublicPageView>('/api/v1/content/view', { path });
  }

  /**
   * M37 Phase 2 (D-452) — "was this useful". Also a bypass route
   * (`/api/v1/content/vote`), rate-limited server-side per (page, address);
   * a 429 here means the caller should stop offering the buttons for a
   * while, not retry immediately.
   */
  vote(path: string, useful: boolean): Observable<VoteAck> {
    return this.api.post<VoteAck>('/api/v1/content/vote', { url_path: path, useful });
  }
}
