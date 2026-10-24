import {
  ChangeDetectionStrategy, Component, DestroyRef, effect, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { MasterDataService, type MasterProvenance } from '@attome/xrm/core/admin/data';
import { forkJoin } from 'rxjs';
import { ContributionsListComponent } from './contributions-list.component';
import { goldenRows, shown, type GoldenRow } from './golden-rows';

/**
 * L1-T9 — the golden record panel on a master entity's form (the record
 * tab `golden`): each attribute's value with the source system it came
 * from, when it was received and the rule that chose it, a pin toggle, and
 * the record's contributions below. An English attribute and its `_ar`
 * twin read as one pair. Pinning needs a steward (or administrator); the
 * server refuses anyone else and the panel says so.
 */
@Component({
  selector: 'xrm-golden-record-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe, ContributionsListComponent],
  styleUrl: './master-data.css',
  template: `
    <section class="md-panel" data-testid="golden-panel" [attr.aria-label]="'masterData.golden.title' | translate">
      @if (error(); as e) {
        <p class="md-error" role="alert" data-testid="golden-error">{{ e }}</p>
      }
      @if (loading()) {
        <p class="md-hint">{{ 'masterData.loading' | translate }}</p>
      } @else if (rows().length === 0) {
        <p class="md-hint" data-testid="golden-empty">{{ 'masterData.golden.empty' | translate }}</p>
      } @else {
        <ul class="md-rows">
          @for (row of rows(); track row.attribute) {
            <li class="md-row" data-testid="golden-row" [attr.data-attribute]="row.attribute">
              <div class="md-row__head">
                <span class="md-row__label">{{ row.label }}</span>
                <button type="button" class="md-pin" data-testid="golden-pin"
                        [attr.aria-pressed]="row.provenance.pinned"
                        [attr.aria-label]="(row.provenance.pinned ? 'masterData.golden.unpin' : 'masterData.golden.pin') | translate: { field: row.label }"
                        [disabled]="busy() === row.attribute"
                        (click)="togglePin(row.provenance)">
                  <i [class]="row.provenance.pinned ? 'las la-thumbtack md-pin--on' : 'las la-thumbtack'" aria-hidden="true"></i>
                </button>
              </div>
              <div class="md-row__values">
                <span class="md-value" dir="auto">{{ shown(row.value) }}</span>
                @if (row.arabic; as ar) {
                  <span class="md-value md-value--ar" lang="ar" dir="rtl" data-testid="golden-arabic">{{ shown(ar.value) }}</span>
                  <button type="button" class="md-pin" data-testid="golden-pin-ar"
                          [attr.aria-pressed]="ar.provenance.pinned"
                          [attr.aria-label]="(ar.provenance.pinned ? 'masterData.golden.unpin' : 'masterData.golden.pin') | translate: { field: ar.attribute }"
                          [disabled]="busy() === ar.attribute"
                          (click)="togglePin(ar.provenance)">
                    <i [class]="ar.provenance.pinned ? 'las la-thumbtack md-pin--on' : 'las la-thumbtack'" aria-hidden="true"></i>
                  </button>
                }
              </div>
              <p class="md-source">
                {{ sourceText(row.provenance) }}
                @if (row.provenance.received_at) {
                  · <time [attr.datetime]="row.provenance.received_at">{{ row.provenance.received_at | localDate: { dateStyle: 'medium', timeStyle: 'short' } }}</time>
                }
                · {{ ruleKey(row.provenance.rule) | translate }}
              </p>
            </li>
          }
        </ul>
      }
      <h3 class="md-subtitle">{{ 'masterData.contributions.title' | translate }}</h3>
      <xrm-master-contributions [entityName]="entityName()" [recordId]="recordId()" />
    </section>
  `,
})
export class GoldenRecordPanelComponent {
  readonly entityName = input.required<string>();
  readonly recordId = input.required<string>();

  protected readonly lang = inject(LangService);
  private readonly svc = inject(MasterDataService);
  private readonly destroyRef = inject(DestroyRef);

  readonly rows = signal<GoldenRow[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  /** The attribute whose pin is being changed. */
  readonly busy = signal<string | null>(null);

  protected readonly shown = shown;

  constructor() {
    effect(() => this.load(this.entityName(), this.recordId()));
  }

  private load(entity: string, id: string): void {
    this.loading.set(true);
    forkJoin({
      fields: this.svc.fields(entity),
      values: this.svc.values(entity, id),
      provenance: this.svc.provenance(entity, id),
    })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: ({ fields, values, provenance }) => {
          this.rows.set(goldenRows(fields, values, provenance.items));
          this.loading.set(false);
        },
        error: (e: ApiError) => {
          this.error.set(this.lang.errorText(e));
          this.loading.set(false);
        },
      });
  }

  sourceText(p: MasterProvenance): string {
    if (p.source_system) {
      return this.lang.translate('masterData.golden.from', {
        system: p.source_system, id: p.external_id ?? '',
      });
    }
    return this.lang.translate('masterData.golden.noSource');
  }

  ruleKey(rule: string): string {
    switch (rule) {
      case 'source_system_rank': return 'masterData.rules.rank';
      case 'pinned': return 'masterData.rules.pinned';
      default: return 'masterData.rules.recent';
    }
  }

  togglePin(p: MasterProvenance): void {
    const entity = this.entityName();
    const id = this.recordId();
    this.busy.set(p.attribute);
    this.error.set(null);
    const call = p.pinned
      ? this.svc.unpin(entity, id, p.attribute)
      : this.svc.pin(entity, id, p.attribute);
    call.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.busy.set(null);
        this.rows.update(rows => rows.map(r => {
          if (r.attribute === p.attribute) {
            return { ...r, provenance: { ...r.provenance, pinned: !p.pinned } };
          }
          if (r.arabic?.attribute === p.attribute) {
            return { ...r, arabic: { ...r.arabic, provenance: { ...r.arabic.provenance, pinned: !p.pinned } } };
          }
          return r;
        }));
      },
      error: (e: ApiError) => {
        this.busy.set(null);
        this.error.set(e.status === 403
          ? this.lang.translate('masterData.notSteward')
          : this.lang.errorText(e));
      },
    });
  }
}
