import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  DataProfileService, fillRate, profileFields,
  type DataProfileRow, type FieldProfile,
} from '@attome/xrm/core/admin/data';

/** One histogram bar: its share of the tallest bucket and its range. */
export interface HistogramBar { height: number; count: number; from: number; to: number; }

/** A number profile's histogram as bars scaled to the tallest bucket. Pure. */
export function histogramBars(field: FieldProfile): HistogramBar[] {
  const h = field.number?.histogram;
  if (!h || h.counts.length === 0) return [];
  const tallest = Math.max(...h.counts, 1);
  return h.counts.map((count, i) => ({
    height: (count * 100) / tallest,
    count,
    from: h.from + i * h.bucket_width,
    to: h.from + (i + 1) * h.bucket_width,
  }));
}

/**
 * L6-T7: an entity's latest data profile on its catalog page — a table of
 * every profiled field (fill rate, distinct values, the most common values,
 * or their shapes when the field is labelled sensitive), and one field's
 * detail: number statistics with a histogram, text lengths, the value
 * shapes and the Arabic-aware measures. A sampled profile says how many
 * rows it read. The histogram's bars follow the page's direction, so they
 * run right to left in Arabic. Read only: profiling itself is started from
 * the data admin, never here.
 */
@Component({
  selector: 'xrm-profile-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, LocalNumberPipe, TranslatePipe],
  styleUrls: ['../governance.css', './profile-panel.component.css'],
  template: `
    <h4>{{ 'governance.catalog.profile.title' | translate }}</h4>
    @if (loading()) {
      <p class="state-msg">{{ 'governance.common.loading' | translate }}</p>
    } @else if (error(); as message) {
      <p class="error-msg" role="alert">{{ message }}</p>
    } @else if (!profile()) {
      <p class="gov-muted" data-profile-none>{{ 'governance.catalog.profile.none' | translate }}</p>
    } @else if (profile(); as p) {
      <p class="gov-muted" data-profile-note>
        @if (p.full_scan || !p.sample_size || p.sample_size === p.row_count) {
          {{ 'governance.catalog.profile.allRows' | translate: { rows: (p.row_count ?? 0 | localNumber) } }}
        } @else {
          {{ 'governance.catalog.profile.sampled' | translate: { sample: (p.sample_size | localNumber), rows: (p.row_count ?? 0 | localNumber) } }}
        }
        @if (p.completed_at) {
          · {{ p.completed_at | localDate: { dateStyle: 'medium', timeStyle: 'short' } }}
        }
      </p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{{ 'governance.catalog.fieldName' | translate }}</th>
              <th scope="col">{{ 'governance.catalog.profile.fill' | translate }}</th>
              <th scope="col">{{ 'governance.catalog.profile.distinct' | translate }}</th>
              <th scope="col">{{ 'governance.catalog.profile.common' | translate }}</th>
            </tr>
          </thead>
          <tbody>
            @for (f of fields(); track f.field) {
              <tr [class.dp-row--open]="openField() === f.field">
                <td>
                  <button type="button" class="btn-text cell-mono" data-profile-field [attr.aria-expanded]="openField() === f.field"
                          (click)="toggle(f.field)">{{ f.field }}</button>
                </td>
                <td>
                  <span class="dp-fill" [style.--dp-fill]="fill(f) + '%'" aria-hidden="true"></span>
                  {{ fill(f) | localNumber: { maximumFractionDigits: 1 } }}%
                </td>
                <td>
                  {{ f.distinct_count | localNumber }}@if (f.distinct_is_lower_bound) {+}
                </td>
                <td>
                  @if (f.masked) {
                    <span class="badge" data-profile-masked>{{ 'governance.catalog.profile.shapes' | translate }}</span>
                  }
                  @for (v of f.top_values.slice(0, 3); track v.value) {
                    <span class="dp-value" [class.dp-shape]="f.masked" dir="ltr" data-profile-value>{{ v.value }}</span>
                  }
                </td>
              </tr>
              @if (openField() === f.field) {
                <tr class="dp-detail-row">
                  <td colspan="4">
                    <div class="dp-detail" data-profile-detail>
                      @if (f.number; as n) {
                        <dl class="dp-facts">
                          <dt>{{ 'governance.catalog.profile.min' | translate }}</dt><dd>{{ n.min | localNumber }}</dd>
                          <dt>{{ 'governance.catalog.profile.median' | translate }}</dt><dd>{{ n.median | localNumber }}</dd>
                          <dt>{{ 'governance.catalog.profile.mean' | translate }}</dt><dd>{{ n.mean | localNumber: { maximumFractionDigits: 2 } }}</dd>
                          <dt>{{ 'governance.catalog.profile.max' | translate }}</dt><dd>{{ n.max | localNumber }}</dd>
                          <dt>{{ 'governance.catalog.profile.outliers' | translate }}</dt><dd>{{ n.outliers | localNumber }}</dd>
                        </dl>
                        <div class="dp-histogram" role="img" data-profile-histogram
                             [attr.aria-label]="'governance.catalog.profile.histogram' | translate">
                          @for (b of bars(f); track $index) {
                            <span class="dp-bar" [style.--dp-bar]="b.height + '%'" [attr.title]="b.count"></span>
                          }
                        </div>
                      }
                      @if (f.length; as l) {
                        <dl class="dp-facts">
                          <dt>{{ 'governance.catalog.profile.shortest' | translate }}</dt><dd>{{ l.min | localNumber }}</dd>
                          <dt>{{ 'governance.catalog.profile.medianLength' | translate }}</dt><dd>{{ l.median | localNumber }}</dd>
                          <dt>{{ 'governance.catalog.profile.longest' | translate }}</dt><dd>{{ l.max | localNumber }}</dd>
                        </dl>
                      }
                      @if (f.date_range; as d) {
                        <dl class="dp-facts">
                          <dt>{{ 'governance.catalog.profile.earliest' | translate }}</dt><dd dir="ltr">{{ d.earliest }}</dd>
                          <dt>{{ 'governance.catalog.profile.latest' | translate }}</dt><dd dir="ltr">{{ d.latest }}</dd>
                        </dl>
                      }
                      @if (f.patterns; as pt) {
                        @if (pt.top_shapes.length > 0) {
                          <p class="dp-label">{{ 'governance.catalog.profile.topShapes' | translate }}</p>
                          <ul class="dp-shapes">
                            @for (s of pt.top_shapes; track s.shape) {
                              <li><span class="dp-value dp-shape" dir="ltr">{{ s.shape }}</span>
                                {{ s.share_pct | localNumber: { maximumFractionDigits: 1 } }}%</li>
                            }
                          </ul>
                        }
                        <p class="dp-label">{{ 'governance.catalog.profile.arabic' | translate }}</p>
                        <dl class="dp-facts" data-profile-arabic>
                          <dt>{{ 'governance.catalog.profile.scriptArabic' | translate }}</dt><dd>{{ pt.arabic.script.arabic | localNumber }}</dd>
                          <dt>{{ 'governance.catalog.profile.scriptLatin' | translate }}</dt><dd>{{ pt.arabic.script.latin | localNumber }}</dd>
                          <dt>{{ 'governance.catalog.profile.scriptMixed' | translate }}</dt><dd>{{ pt.arabic.script.mixed | localNumber }}</dd>
                          <dt>{{ 'governance.catalog.profile.easternDigits' | translate }}</dt><dd>{{ pt.arabic.digits.eastern | localNumber }}</dd>
                          <dt>{{ 'governance.catalog.profile.diacritics' | translate }}</dt><dd>{{ pt.arabic.with_diacritics | localNumber }}</dd>
                          <dt>{{ 'governance.catalog.profile.hijri' | translate }}</dt><dd>{{ pt.arabic.dates.hijri | localNumber }}</dd>
                        </dl>
                      }
                    </div>
                  </td>
                </tr>
              }
            }
          </tbody>
        </table>
      </div>
    }
  `,
})
export class ProfilePanelComponent {
  private readonly svc = inject(DataProfileService);
  private readonly destroyRef = inject(DestroyRef);

  /** The entity whose latest profile is shown. */
  readonly entity = input.required<string>();

  readonly profile = signal<DataProfileRow | null>(null);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly openField = signal<string | null>(null);

  readonly fields = computed(() => {
    const p = this.profile();
    return p ? profileFields(p) : [];
  });

  constructor() {
    effect(() => {
      const entity = this.entity();
      untracked(() => this.load(entity));
    });
  }

  fill(field: FieldProfile): number {
    return fillRate(field);
  }

  bars(field: FieldProfile): HistogramBar[] {
    return histogramBars(field);
  }

  toggle(field: string): void {
    this.openField.update(open => (open === field ? null : field));
  }

  private load(entity: string): void {
    this.loading.set(true);
    this.error.set(null);
    this.openField.set(null);
    this.svc.latest(entity).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: p => { this.profile.set(p); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }
}
