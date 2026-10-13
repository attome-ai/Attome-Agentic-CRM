import { computed, inject, Injectable, signal } from '@angular/core';
import { ApiComponents, ApiError, ApiService, AuthService, Page } from '@attome/base';
import { Observable, catchError, map, of, tap } from 'rxjs';

/** `GET /api/v1/admin/changesets` item (Solution 7, D-785). */
export type ChangesetSummary = ApiComponents['schemas']['ChangesetSummary'];

/**
 * Where the changeset list stands:
 * - `idle`: never asked;
 * - `ready`: the list loaded — authoring is open on this deployment;
 * - `unavailable`: the server refused it (production's authoring gate, 403
 *   `metadata_authoring_locked`, or a non-admin's 403) — the indicator hides;
 * - `error`: any other failure, shown as such.
 */
export type ChangesetListStatus = 'idle' | 'loading' | 'ready' | 'unavailable' | 'error';

/** The one-based list route's page size: a developer rarely holds more than a handful open. */
const OPEN_PAGE_SIZE = 100;

/**
 * Solution 7 (D-785) — which changeset the metadata designer is recording
 * into, and so which layer it is editing.
 *
 * The picked id lives in `ApiService` (`setChangeset`), which sends it as
 * `X-Attome-Changeset` on every mutating request; this service only lists the
 * open changesets and forwards the pick. Nothing is picked implicitly: with no
 * pick the server itself uses the caller's single open changeset (else 409
 * `changeset_ambiguous`/`changeset_required` in required mode, or an automatic
 * `project` changeset in auto mode), and `editingLayer` mirrors that rule so
 * the owner-layer badge predicts a `layer_mismatch` refusal before a save.
 *
 * Source of truth is the server; this is a per-tab view rebuilt by
 * `refresh()`. Presentation only — the recorder enforces every rule.
 */
@Injectable({ providedIn: 'root' })
export class ChangesetContextService {
  private readonly api  = inject(ApiService);
  private readonly auth = inject(AuthService);

  private readonly _open   = signal<ChangesetSummary[]>([]);
  private readonly _status = signal<ChangesetListStatus>('idle');

  /** Open changesets, newest first (every author's: any admin may record into one). */
  readonly open   = this._open.asReadonly();
  readonly status = this._status.asReadonly();

  /** The id sent as `X-Attome-Changeset`, or `null`. */
  readonly selectedId = this.api.activeChangeset;

  readonly selected = computed<ChangesetSummary | null>(() => {
    const id = this.selectedId();
    return id ? this._open().find(c => c.id === id) ?? null : null;
  });

  /**
   * The changeset a write would record into: the picked one, else the
   * signed-in user's only open changeset (the server's no-header rule), else
   * `null` (none, or ambiguous).
   */
  readonly effective = computed<ChangesetSummary | null>(() => {
    const picked = this.selected();
    if (picked) return picked;
    const me = this.auth.userId();
    const mine = me ? this._open().filter(c => c.author_ref === me) : [];
    return mine.length === 1 ? mine[0] : null;
  });

  /**
   * The layer edits are made in, or `null` when no changeset applies (the
   * owner-layer badge then assumes automatic changesets' `project` layer).
   */
  readonly editingLayer = computed<string | null>(() => this.effective()?.layer ?? null);

  /** Re-reads the open changesets; a pick that is no longer open is cleared. */
  refresh(): Observable<ChangesetListStatus> {
    this._status.set('loading');
    return this.api.get<Page<ChangesetSummary>>('/api/v1/admin/changesets', {
      status: 'open', page: '1', page_size: String(OPEN_PAGE_SIZE),
    }).pipe(
      tap(res => {
        this._open.set(res.items);
        const id = this.selectedId();
        if (id && !res.items.some(c => c.id === id)) this.api.setChangeset(null);
      }),
      map((): ChangesetListStatus => 'ready'),
      catchError((err: ApiError) => {
        this._open.set([]);
        return of<ChangesetListStatus>(
          err?.kind === 'forbidden' || err?.kind === 'authoring_locked' || err?.kind === 'feature_hidden'
            ? 'unavailable'
            : 'error',
        );
      }),
      tap(status => this._status.set(status)),
    );
  }

  /** Records later writes into `id`, or clears the pick with `null`. */
  select(id: string | null): void {
    this.api.setChangeset(id);
  }
}
