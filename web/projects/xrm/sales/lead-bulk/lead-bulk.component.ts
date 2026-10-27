import { ChangeDetectionStrategy, Component, inject, input, signal } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import { catchError, concatMap, from, map, Observable, of, switchMap, toArray } from 'rxjs';
import { DISQUALIFY_REASONS, DisqualifyReason, LeadConvertApiService } from '../lead-convert-api';

/** Each reason's catalog key. */
export const REASON_KEYS: Record<DisqualifyReason, string> = {
  no_budget: 'leadConvert.reasons.no_budget',
  no_need: 'leadConvert.reasons.no_need',
  no_authority: 'leadConvert.reasons.no_authority',
  bad_timing: 'leadConvert.reasons.bad_timing',
  competitor: 'leadConvert.reasons.competitor',
  unreachable: 'leadConvert.reasons.unreachable',
  duplicate: 'leadConvert.reasons.duplicate',
  other: 'leadConvert.reasons.other',
};

/** Leads one bulk action works on, at most. */
export const LEAD_BULK_MAX = 100;

/** A bulk action's outcome. */
export interface LeadBulkResult {
  done: number;
  failed: number;
}

/**
 * D3-T3: convert or disqualify the selected leads from the lead list. Convert
 * creates the account, contact and opportunity for each (no links: a lead
 * with matches is converted from its own Convert tab); Disqualify moves each
 * to `disqualified` with the reason chosen. Each lead is read for its version
 * first and sent alone, one after another, so a lead someone else changed, a
 * lead in the wrong state or one the person may not change fails by itself
 * and the rest go on. The server checks every one as a single change.
 *
 * Rendered by the entity list through `NgComponentOutlet`, so it takes the
 * list's reload as the `finished` input instead of an output.
 */
@Component({
  selector: 'xrm-sales-lead-bulk',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <span class="lb" data-testid="lead-bulk">
      <button type="button" class="btn btn-secondary" data-lead-bulk-convert
              [disabled]="disabled() || busy() || !recordIds().length" (click)="convertAll()">
        <i class="las la-arrow-right" aria-hidden="true"></i> {{ 'leadConvert.bulkConvert' | translate }}
      </button>
      <select [attr.aria-label]="'leadConvert.reason' | translate" [disabled]="busy()"
              (change)="pickReason($event)" data-lead-bulk-reason>
        @for (r of reasons; track r) {
          <option [value]="r" [selected]="r === reason()">{{ reasonKeys[r] | translate }}</option>
        }
      </select>
      <button type="button" class="btn btn-secondary" data-lead-bulk-disqualify
              [disabled]="disabled() || busy() || !recordIds().length" (click)="disqualifyAll()">
        {{ 'leadConvert.bulkDisqualify' | translate }}
      </button>
      @if (tooMany()) {
        <span class="lb-error" role="alert">{{ 'leadConvert.bulkTooMany' | translate: { max: max } }}</span>
      }
      @if (result(); as r) {
        <span role="status" data-lead-bulk-result>{{ 'leadConvert.bulkResult' | translate: { done: r.done, failed: r.failed } }}</span>
      }
    </span>
  `,
  styles: [`
    .lb { display: inline-flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
    .lb-error { color: var(--color-danger); }
  `],
})
export class LeadBulkComponent {
  private readonly leads = inject(LeadConvertApiService);

  readonly recordIds = input.required<readonly string[]>();
  readonly disabled = input(false);
  /** Called after an action, so the list reloads. */
  readonly finished = input<(() => void) | null>(null);

  readonly reasons = DISQUALIFY_REASONS;
  readonly reasonKeys = REASON_KEYS;
  readonly max = LEAD_BULK_MAX;
  readonly reason = signal<DisqualifyReason>('no_need');
  readonly busy = signal(false);
  readonly tooMany = signal(false);
  readonly result = signal<LeadBulkResult | null>(null);

  pickReason(event: Event): void {
    const value = (event.target as HTMLSelectElement).value;
    const reason = DISQUALIFY_REASONS.find(r => r === value);
    if (reason) this.reason.set(reason);
  }

  convertAll(): void {
    this.run(id => this.leads.lead(id).pipe(
      switchMap(lead => this.leads.convert(id, {}, lead.row_version)),
    ));
  }

  disqualifyAll(): void {
    const reason = this.reason();
    this.run(id => this.leads.lead(id).pipe(
      switchMap(lead => this.leads.disqualify(id, reason, lead.row_version)),
    ));
  }

  private run(one: (id: string) => Observable<unknown>): void {
    const ids = [...this.recordIds()];
    this.tooMany.set(ids.length > LEAD_BULK_MAX);
    if (!ids.length || ids.length > LEAD_BULK_MAX || this.busy()) return;
    this.busy.set(true);
    this.result.set(null);
    from(ids).pipe(
      concatMap(id => one(id).pipe(map(() => true), catchError(() => of(false)))),
      toArray(),
    ).subscribe(outcomes => {
      const done = outcomes.filter(Boolean).length;
      this.busy.set(false);
      this.result.set({ done, failed: outcomes.length - done });
      this.finished()?.();
    });
  }
}
