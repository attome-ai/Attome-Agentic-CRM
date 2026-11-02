import {
  ChangeDetectionStrategy, Component, DestroyRef, Injectable, OnInit, computed, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import type { Observable } from 'rxjs';
import { LangService, LocalDatePipe, LocalNumberPipe, SdkService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';

/** One planned line's move (F11-T6 `LineChange`). */
export interface LineChange {
  line_id: string;
  fiscal_period: string;
  from: string;
  to: string;
}

/** One obligation's change (F11-T6 `ObligationPreview`). */
export interface ObligationPreview {
  obligation_id: string;
  recognised: string;
  old_total: string;
  new_total: string;
  lines: LineChange[];
}

/** A stored change preview (`contract_change.preview_json`). */
export interface ChangePreview {
  change_id: string;
  contract_id: string;
  change_kind: string;
  treatment: string;
  overridden: boolean;
  status: string;
  obligations: ObligationPreview[];
}

/** A line as the page shows it. */
export interface PeriodRow {
  period: string;
  /** The first day of the period, for the calendar-aware date pipe. */
  day: string;
  from: number;
  to: number;
  difference: number;
  /** `up`, `down` or `same`, for the difference's colour. */
  direction: 'up' | 'down' | 'same';
}

/** Per-period rows of an obligation's preview, in period order. Pure. */
export function periodRows(obligation: ObligationPreview): PeriodRow[] {
  return [...obligation.lines]
    .sort((a, b) => a.fiscal_period.localeCompare(b.fiscal_period))
    .map(line => {
      const from = Number(line.from);
      const to = Number(line.to);
      const difference = Math.round((to - from) * 100) / 100;
      return {
        period: line.fiscal_period,
        day: `${line.fiscal_period}-01`,
        from,
        to,
        difference,
        direction: difference > 0 ? 'up' : difference < 0 ? 'down' : 'same',
      };
    });
}

/**
 * F11-T6 routes (`crates/engine/attome-ledger/src/revrec/change.rs`): the
 * stored preview is read from the `contract_change` record; apply and
 * discard are the ledger's own routes.
 */
@Injectable({ providedIn: 'root' })
export class RevrecChangeService {
  private readonly sdk = inject(SdkService);

  record(id: string): Observable<{ data: { preview_json?: string | null; status?: string | null } }> {
    return this.sdk.get(`/api/v1/contract_change/${id}`);
  }

  apply(id: string): Observable<{ change_id: string; lines: number }> {
    return this.sdk.post(`/api/v1/ledger/revrec/changes/${id}/apply`, { body: {} });
  }

  discard(id: string): Observable<unknown> {
    return this.sdk.post(`/api/v1/ledger/revrec/changes/${id}/discard`, { body: {} });
  }
}

/**
 * F11-T13 — a contract change's preview: per obligation, the old and new
 * amount of every open period (formatted in the reader's calendar, Hijri or
 * Gregorian) and the difference, then Apply or Discard. Right to left in
 * Arabic through logical properties only.
 */
@Component({
  selector: 'xrm-revrec-change-preview',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, LocalNumberPipe, TranslatePipe],
  styleUrls: ['./revrec-change-preview.component.css'],
  templateUrl: './revrec-change-preview.component.html',
  host: { '[attr.dir]': "lang.isRtl() ? 'rtl' : 'ltr'" },
})
export class RevrecChangePreviewComponent implements OnInit {
  readonly changeId = input.required<string>();

  protected readonly lang = inject(LangService);
  private readonly svc = inject(RevrecChangeService);
  private readonly destroyRef = inject(DestroyRef);

  readonly monthFmt: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'long' };
  readonly preview = signal<ChangePreview | null>(null);
  readonly loading = signal(true);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly done = signal<'applied' | 'discarded' | null>(null);

  readonly obligations = computed(() =>
    (this.preview()?.obligations ?? []).map(o => ({ preview: o, rows: periodRows(o) })),
  );
  readonly open = computed(() => this.preview()?.status === 'previewed' && this.done() === null);

  ngOnInit(): void {
    this.svc.record(this.changeId()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        this.loading.set(false);
        const raw = res.data.preview_json;
        try {
          this.preview.set(raw ? (JSON.parse(raw) as ChangePreview) : null);
        } catch {
          this.error.set(this.lang.translate('revrecChange.unreadable'));
        }
      },
      error: (err: ApiError) => { this.loading.set(false); this.error.set(this.lang.errorText(err)); },
    });
  }

  apply(): void {
    this.act('applied');
  }

  discard(): void {
    this.act('discarded');
  }

  private act(outcome: 'applied' | 'discarded'): void {
    if (this.busy() || !this.open()) return;
    this.busy.set(true);
    this.error.set(null);
    const call = outcome === 'applied' ? this.svc.apply(this.changeId()) : this.svc.discard(this.changeId());
    call.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => { this.busy.set(false); this.done.set(outcome); },
      error: (err: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(err)); },
    });
  }
}
