import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { LangService, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  DataQualityService, MAX_FIX_RECORDS, QUALITY_FIXES,
  type QualityFixBody, type QualityFixKind, type QualityFixPreview, type QualityFixSubmitted,
} from '@attome/xrm/core/admin/data';

/** The most issues one list page holds (`attome_types::MAX_PAGE_SIZE`). */
const ISSUE_PAGE = 200;

/**
 * L2-T8: the Fixes tab of the data-quality screen. A fix runs over the
 * records with open issues on one field (at most 500): the preview shows how
 * many records it changes and the first ones before and after; applying it
 * is one bulk edit, and its undo list puts the records back.
 */
@Component({
  selector: 'xrm-quality-fixes',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalNumberPipe, TranslatePipe],
  styleUrls: ['../../../../styles/admin-page.css', '../governance.css', './data-quality.component.css'],
  template: `
    <section class="card" aria-labelledby="dq-fixes-title">
      <h3 id="dq-fixes-title">{{ 'governance.quality.fixes.title' | translate }}</h3>
      <p class="subtitle">{{ 'governance.quality.fixes.subtitle' | translate: { max: maxRecords } }}</p>
      <form class="dq-rule-form" (ngSubmit)="preview()">
        <label>{{ 'governance.common.entity' | translate }}
          <input class="mono-input" name="entity" [ngModel]="entityName()" (ngModelChange)="entityName.set($event)" required />
        </label>
        <label>{{ 'governance.quality.field' | translate }}
          <input class="mono-input" name="attribute" [ngModel]="attribute()" (ngModelChange)="attribute.set($event)" required />
        </label>
        <label>{{ 'governance.quality.fixes.fix' | translate }}
          <select name="fix" [ngModel]="fix()" (ngModelChange)="fix.set($event)">
            @for (f of fixes; track f) {
              <option [value]="f">{{ 'governance.quality.fixes.kinds.' + f | translate }}</option>
            }
          </select>
        </label>
        @if (fix() === 'phone_e164') {
          <label>{{ 'governance.quality.fixes.country' | translate }}
            <input class="mono-input" name="country" maxlength="2" [ngModel]="country()" (ngModelChange)="country.set($event)" />
          </label>
        }
        <div class="dq-rule-form__actions">
          <button type="submit" class="btn-primary" data-fix-preview [disabled]="busy() || !entityName().trim() || !attribute().trim()">
            {{ 'governance.quality.fixes.preview' | translate }}
          </button>
        </div>
      </form>

      @if (error(); as message) { <p class="error-msg" role="alert">{{ message | translate }}</p> }

      @if (previewed(); as p) {
        <div class="dq-fix-preview" data-fix-result>
          <p>{{ 'governance.quality.fixes.counts' | translate: { matched: p.matched, change: p.to_change, unchanged: p.unchanged } }}</p>
          @if (p.samples.length > 0) {
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col">{{ 'governance.quality.record' | translate }}</th>
                    <th scope="col">{{ 'governance.quality.fixes.change' | translate }}</th>
                  </tr>
                </thead>
                <tbody>
                  @for (s of p.samples; track s.id) {
                    <tr>
                      <td class="cell-mono">{{ s.id }}</td>
                      <td>
                        <span class="cell-mono">{{ valueOf(s.before) }}</span>
                        <span class="dq-arrow" aria-hidden="true">{{ arrow() }}</span>
                        <span class="cell-mono">{{ valueOf(s.after) }}</span>
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }
          <button type="button" class="btn-primary" data-fix-apply (click)="apply()" [disabled]="busy() || p.to_change === 0">
            <i class="las la-check" aria-hidden="true"></i>
            {{ 'governance.quality.fixes.apply' | translate: { count: p.to_change } }}
          </button>
        </div>
      }

      @if (applied(); as a) {
        <p class="gov-notice" role="status" aria-live="polite" data-fix-applied>
          @if (a.approval_request_id) {
            {{ 'governance.quality.fixes.awaitingApproval' | translate }}
          } @else {
            {{ 'governance.quality.fixes.applied' | translate: { count: a.total - a.unchanged } }}
          }
        </p>
        @if (a.undo.length > 0 && !undone()) {
          <button type="button" class="btn-ghost" data-fix-undo (click)="undo()" [disabled]="busy()">
            <i class="las la-undo" aria-hidden="true"></i> {{ 'governance.quality.fixes.undo' | translate }}
          </button>
        }
        @if (undone()) { <p class="gov-notice" role="status">{{ 'governance.quality.fixes.undone' | translate }}</p> }
      }
    </section>
  `,
})
export class QualityFixesComponent implements OnInit {
  private readonly svc = inject(DataQualityService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  /** The entity filter of the screen, to start from. */
  readonly entity = input('');

  readonly fixes = QUALITY_FIXES;
  readonly maxRecords = MAX_FIX_RECORDS;

  readonly entityName = signal('');
  readonly attribute = signal('');
  readonly fix = signal<QualityFixKind>('trim_spaces');
  readonly country = signal('SA');
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly previewed = signal<QualityFixPreview | null>(null);
  readonly applied = signal<QualityFixSubmitted | null>(null);
  readonly undone = signal(false);
  /** The records the preview was made for, so apply changes the same ones. */
  private ids: string[] = [];

  ngOnInit(): void {
    this.entityName.set(this.entity().trim());
  }

  /** Before and after read in the page's own direction. */
  readonly arrow = computed(() => (this.lang.isRtl() ? '←' : '→'));

  /** The one attribute's value of a sample's before or after. */
  valueOf(values: Record<string, unknown>): string {
    const value = values[this.attribute().trim()];
    return value === null || value === undefined ? '' : String(value);
  }

  private body(): QualityFixBody {
    const fix = this.fix() === 'phone_e164'
      ? { fix: 'phone_e164', country: this.country().trim().toUpperCase() }
      : this.fix();
    return {
      entity: this.entityName().trim(),
      attribute: this.attribute().trim(),
      fix: fix as unknown as QualityFixBody['fix'],
      ids: this.ids,
    };
  }

  /** The records with open issues on the field, then the fix's preview. */
  preview(): void {
    this.busy.set(true);
    this.error.set(null);
    this.previewed.set(null);
    this.applied.set(null);
    this.undone.set(false);
    const attribute = this.attribute().trim();
    // The API pages issues 200 at a time; a fix takes up to 500 records.
    this.svc.listIssues({ entity: this.entityName().trim(), status: 'open' }, 1, ISSUE_PAGE)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: page => {
          this.ids = [...new Set(
            page.items.filter(i => i.field_logicalname === attribute).map(i => i.record_id),
          )].slice(0, MAX_FIX_RECORDS);
          if (this.ids.length === 0) {
            this.busy.set(false);
            this.error.set('governance.quality.fixes.nothing');
            return;
          }
          this.svc.previewFix(this.body()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
            next: p => { this.previewed.set(p); this.busy.set(false); },
            error: (e: ApiError) => { this.error.set(e.message); this.busy.set(false); },
          });
        },
        error: (e: ApiError) => { this.error.set(e.message); this.busy.set(false); },
      });
  }

  apply(): void {
    this.busy.set(true);
    this.error.set(null);
    this.svc.applyFix(this.body()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: submitted => { this.applied.set(submitted); this.previewed.set(null); this.busy.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.busy.set(false); },
    });
  }

  undo(): void {
    const submitted = this.applied();
    if (!submitted) return;
    this.busy.set(true);
    this.svc.undoFix(this.entityName().trim(), submitted.undo).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => { this.undone.set(true); this.busy.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.busy.set(false); },
    });
  }
}
