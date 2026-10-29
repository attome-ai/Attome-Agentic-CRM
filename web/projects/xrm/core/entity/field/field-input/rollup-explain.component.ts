import { ChangeDetectionStrategy, Component, effect, inject, input, signal, untracked } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';

import { entityFormRoute } from '../../services/entity-url.utils';

/** `GET /api/v1/{entity}/{id}/rollups/{attribute}/explain`'s answer. */
export interface RollupExplanation {
  function: string;
  mode: string;
  path: string[];
  field: string | null;
  filter: string | null;
  window_days: number | null;
  value: unknown;
  counted: number;
  hidden: number;
  records: { id: string; value: unknown }[];
  truncated: boolean;
}

/**
 * A10-T6: the drill-down from a rollup's value on a record: how it is
 * computed and the related records it counts that the reader may read
 * (the others are counted only), each opening its record.
 */
@Component({
  selector: 'xrm-rollup-explain',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  template: `
    @if (error(); as message) {
      <p class="rx-error" role="alert">{{ message }}</p>
    } @else if (explanation(); as x) {
      <div class="rx" data-testid="rollup-explain">
        <p class="rx-how">
          {{ 'rollupExplain.how' | translate: { function: x.function, field: x.field ?? '—', path: x.path.join(' → '), counted: x.counted } }}
          @if (x.filter) { <code dir="ltr">{{ x.filter }}</code> }
        </p>
        <ul class="rx-list">
          @for (r of x.records; track r.id) {
            <li><a [routerLink]="recordRoute()" [queryParams]="{ id: r.id }" dir="ltr">{{ r.id }}</a>
              @if (r.value !== null && r.value !== undefined) { <span class="rx-value" dir="ltr">{{ r.value }}</span> }
            </li>
          }
        </ul>
        @if (x.hidden > 0) {
          <p class="rx-hint" data-testid="rollup-hidden">{{ 'rollupExplain.hidden' | translate: { count: x.hidden } }}</p>
        }
        @if (x.truncated) {
          <p class="rx-hint">{{ 'rollupExplain.truncated' | translate }}</p>
        }
      </div>
    } @else {
      <p class="rx-hint" role="status">{{ 'rollupExplain.loading' | translate }}</p>
    }
  `,
  styles: [`
    .rx { display: flex; flex-direction: column; gap: .25rem; font-size: .8125rem; }
    .rx-how { margin: 0; }
    .rx-list { margin: 0; padding-inline-start: 1rem; max-block-size: 12rem; overflow: auto; }
    .rx-value { margin-inline-start: .5rem; color: var(--color-text-secondary); }
    .rx-hint { margin: 0; color: var(--color-text-secondary); }
    .rx-error { margin: 0; color: var(--color-danger); }
  `],
})
export class RollupExplainComponent {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly entity = input.required<string>();
  readonly recordId = input.required<string>();
  readonly attribute = input.required<string>();

  readonly explanation = signal<RollupExplanation | null>(null);
  readonly error = signal<string | null>(null);

  constructor() {
    effect(() => {
      const path = `/api/v1/${encodeURIComponent(this.entity())}/${encodeURIComponent(this.recordId())}`
        + `/rollups/${encodeURIComponent(this.attribute())}/explain`;
      untracked(() => {
        this.error.set(null);
        this.api.get<RollupExplanation>(path).subscribe({
          next: x => this.explanation.set(x),
          error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
        });
      });
    });
  }

  /** The related records' form: the last step's entity. */
  recordRoute(): string[] {
    const path = this.explanation()?.path ?? [];
    return entityFormRoute(path[path.length - 1]?.split('.')[0] ?? '');
  }
}
