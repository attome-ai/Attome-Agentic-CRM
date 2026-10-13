import {
  ChangeDetectionStrategy, Component, OnDestroy, OnInit, computed, inject, input, output, signal,
} from '@angular/core';
import { firstValueFrom, from, of } from 'rxjs';
import type { Subscription } from 'rxjs';
import { catchError, map, mergeMap, toArray } from 'rxjs/operators';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { EntityService } from '../services/entity.service';
import {
  RecordSharingService, SHARE_CAPABILITIES,
} from './record-sharing.service';
import type { RecordShareItem, ShareCapability } from './record-sharing.service';
import {
  AssignOutcome, PRINCIPAL_SOURCES, Principal, PrincipalKind, RecordAccessMode, reassignBody, shareBody,
  summarizeAssign,
} from './record-access';

/** In-flight reassign calls during a bulk Assign — bounded, never one burst. */
const ASSIGN_CONCURRENCY = 4;
/** In-flight principal-name reads while listing a record's shares. */
const LABEL_CONCURRENCY = 4;

interface ShareRow {
  share: RecordShareItem;
  label: string;
}

/**
 * U7 Phase A — the Assign / Share dialog behind `<xrm-record-access-actions>`.
 *
 * - **Assign**: pick a user or team; each record is reassigned by its own
 *   `PUT …/record-shares/reassign-owner` call (the route is per record and
 *   atomic per record), and the dialog reports how many succeeded and why the
 *   others failed.
 * - **Share** (one record): the record's current shares with Revoke, and a
 *   form to grant a user or team `view`, `action` or `deny`.
 *
 * Every route is admin-only server-side; nothing here decides access.
 */
@Component({
  selector: 'xrm-record-access-dialog',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  templateUrl: './record-access-dialog.component.html',
  styleUrl: './record-access-dialog.component.css',
})
export class RecordAccessDialogComponent implements OnInit, OnDestroy {
  readonly mode      = input.required<RecordAccessMode>();
  readonly entity    = input.required<string>();
  readonly recordIds = input.required<readonly string[]>();

  /** `true` when an owner or a share changed, so the host refreshes. */
  readonly closed = output<boolean>();

  private readonly sharing   = inject(RecordSharingService);
  private readonly entitySvc = inject(EntityService);
  private readonly lang      = inject(LangService);

  readonly capabilities = SHARE_CAPABILITIES;

  // ── Principal picker ─────────────────────────────────────────────────────
  readonly principalKind = signal<PrincipalKind>('user');
  readonly search        = signal('');
  readonly results       = signal<Principal[]>([]);
  readonly searching     = signal(false);
  readonly principal     = signal<Principal | null>(null);
  private searchSub: Subscription | null = null;
  private searchTimer: ReturnType<typeof setTimeout> | null = null;

  // ── Assign ───────────────────────────────────────────────────────────────
  readonly busy    = signal(false);
  readonly summary = signal<{ succeeded: number; failed: AssignOutcome[] } | null>(null);
  readonly error   = signal<string | null>(null);

  // ── Share ────────────────────────────────────────────────────────────────
  readonly capability    = signal<ShareCapability>('view');
  readonly shares        = signal<ShareRow[]>([]);
  readonly sharesLoading = signal(false);
  private changedAnything = false;

  readonly recordCount = computed(() => this.recordIds().length);

  ngOnInit(): void {
    this.runSearch('');
    if (this.mode() === 'share') this.loadShares();
  }

  ngOnDestroy(): void {
    this.searchSub?.unsubscribe();
    if (this.searchTimer) clearTimeout(this.searchTimer);
  }

  close(): void {
    if (this.busy()) return;
    this.closed.emit(this.changedAnything);
  }

  // ── Picker ───────────────────────────────────────────────────────────────

  setKind(kind: string): void {
    if (kind !== 'user' && kind !== 'team') return;
    this.principalKind.set(kind);
    this.principal.set(null);
    this.search.set('');
    this.runSearch('');
  }

  onSearch(value: string): void {
    this.search.set(value);
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => this.runSearch(value), 200);
  }

  pick(principal: Principal): void { this.principal.set(principal); }

  private runSearch(term: string): void {
    const kind = this.principalKind();
    const source = PRINCIPAL_SOURCES[kind];
    this.searchSub?.unsubscribe();
    this.searching.set(true);
    this.searchSub = this.entitySvc.lookupSearch(source.entity, term, source.displayField).subscribe({
      next: res => {
        this.searching.set(false);
        this.results.set(res.data
          .map(r => ({ kind, id: r.id, label: String(r.data[source.displayField] ?? '').trim() }))
          .filter(p => p.label !== ''));
      },
      error: () => { this.searching.set(false); this.results.set([]); },
    });
  }

  // ── Assign ───────────────────────────────────────────────────────────────

  async assign(): Promise<void> {
    const principal = this.principal();
    const ids = [...this.recordIds()];
    if (!principal || !ids.length || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    const entity = this.entity();
    const outcomes = await firstValueFrom(from(ids).pipe(
      mergeMap(recordId => this.sharing.reassignOwner(reassignBody(entity, recordId, principal)).pipe(
        map((): AssignOutcome => ({ recordId, ok: true })),
        catchError((err: ApiError) => of<AssignOutcome>({ recordId, ok: false, error: err.message })),
      ), ASSIGN_CONCURRENCY),
      toArray(),
    ));
    const summary = summarizeAssign(outcomes);
    if (summary.succeeded > 0) this.changedAnything = true;
    this.summary.set(summary);
    this.busy.set(false);
  }

  // ── Share ────────────────────────────────────────────────────────────────

  setCapability(value: string): void {
    if ((SHARE_CAPABILITIES as readonly string[]).includes(value)) this.capability.set(value as ShareCapability);
  }

  capabilityLabel(capability: string): string {
    return `recordAccess.capability.${capability}`;
  }

  grant(): void {
    const principal = this.principal();
    const recordId = this.recordIds()[0];
    if (!principal || !recordId || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.sharing.createRecordShare(shareBody(this.entity(), recordId, principal, this.capability())).subscribe({
      next: () => {
        this.busy.set(false);
        this.changedAnything = true;
        this.principal.set(null);
        this.loadShares();
      },
      error: (err: ApiError) => { this.busy.set(false); this.error.set(err.message); },
    });
  }

  revoke(row: ShareRow): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.sharing.deleteRecordShare(row.share.id).subscribe({
      next: () => {
        this.busy.set(false);
        this.changedAnything = true;
        this.shares.update(list => list.filter(r => r.share.id !== row.share.id));
      },
      error: (err: ApiError) => { this.busy.set(false); this.error.set(err.message); },
    });
  }

  private loadShares(): void {
    const recordId = this.recordIds()[0];
    if (!recordId) return;
    this.sharesLoading.set(true);
    this.sharing.listRecordShares(this.entity(), recordId).subscribe({
      next: shares => {
        this.shares.set(shares.map(share => ({ share, label: share.principal_id })));
        this.sharesLoading.set(false);
        this.resolveLabels(shares);
      },
      error: (err: ApiError) => { this.sharesLoading.set(false); this.error.set(err.message); },
    });
  }

  /** Shows each share's user email / team name instead of its id — best
   * effort: a principal that cannot be read keeps showing its id. */
  private resolveLabels(shares: readonly RecordShareItem[]): void {
    const principals = new Map<string, PrincipalKind>();
    for (const s of shares) {
      if (s.principal_type === 'user' || s.principal_type === 'team') principals.set(s.principal_id, s.principal_type);
    }
    from([...principals]).pipe(
      mergeMap(([id, kind]) => {
        const source = PRINCIPAL_SOURCES[kind];
        return this.entitySvc.get(source.entity, id).pipe(
          map(r => [id, String(r.data[source.displayField] ?? id)] as const),
          catchError(() => of([id, id] as const)),
        );
      }, LABEL_CONCURRENCY),
      toArray(),
    ).subscribe(pairs => {
      const labels = new Map(pairs);
      this.shares.update(list => list.map(r => ({ ...r, label: labels.get(r.share.principal_id) ?? r.label })));
    });
  }

  principalKindLabel(kind: string): string {
    return kind === 'team' ? 'recordAccess.team' : 'recordAccess.user';
  }

  failureLine(outcome: AssignOutcome): string {
    return this.lang.translate('recordAccess.failedRecord', { id: outcome.recordId, reason: outcome.error ?? '' });
  }
}
