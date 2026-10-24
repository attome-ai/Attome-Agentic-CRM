import { ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { LineageService, type ImpactChange, type ImpactReport } from '@attome/xrm/core/admin/data';

/**
 * L5-T7: the impact of a draft change, shown in the change's preview
 * (`GET /api/v1/admin/lineage/impact`): the definitions it would break
 * first (a deleted or retyped attribute that a dashboard, metric or model
 * reads and no field hook adjusts; the server refuses the change with the
 * same list), then every definition downstream of it by depth. Items the
 * caller may not see are only counted.
 */
@Component({
  selector: 'xrm-lineage-impact',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./lineage.component.css'],
  template: `
    <section class="li" aria-labelledby="li-title" data-impact>
      <h4 id="li-title">{{ 'governance.lineage.impact.title' | translate }}</h4>
      @if (loading()) {
        <p class="state-msg">{{ 'governance.common.loading' | translate }}</p>
      } @else if (error(); as e) {
        <p class="error-msg" role="alert">{{ e }}</p>
      } @else if (report(); as r) {
        @if (r.breaking.length > 0) {
          <p class="li-breaking-title" role="alert">{{ 'governance.lineage.impact.breaking' | translate: { count: r.breaking.length } }}</p>
          <ul class="li-list li-list--breaking" data-impact-breaking>
            @for (b of r.breaking; track b.from_kind + b.from_ref) {
              <li><span class="badge">{{ b.from_kind }}</span> {{ b.from_label }} <span class="hint">{{ b.edge_kind }}</span></li>
            }
          </ul>
        }
        @if (r.affected.length === 0) {
          <p class="gov-muted" data-impact-none>{{ 'governance.lineage.impact.none' | translate }}</p>
        } @else {
          <p>{{ 'governance.lineage.impact.affected' | translate: { count: r.affected.length } }}</p>
          <ul class="li-list" data-impact-affected>
            @for (a of affected(); track a.from_kind + a.from_ref) {
              <li>
                <span class="badge">{{ a.from_kind }}</span> {{ a.from_label }}
                <span class="hint">
                  {{ (a.depth === 1 ? 'governance.lineage.impact.direct' : 'governance.lineage.impact.indirect') | translate: { depth: a.depth } }}
                  · {{ a.edge_kind }}
                  @if (!a.attribute_level) { · {{ 'governance.lineage.impact.entityLevel' | translate }} }
                </span>
              </li>
            }
          </ul>
        }
        @if (r.hidden > 0) {
          <p class="hint">{{ 'governance.lineage.impact.hidden' | translate: { count: r.hidden } }}</p>
        }
      }
    </section>
  `,
})
export class ImpactPanelComponent {
  private readonly svc = inject(LineageService);
  private readonly destroyRef = inject(DestroyRef);

  readonly entity = input.required<string>();
  readonly attribute = input<string | null>(null);
  readonly change = input<ImpactChange>('other');

  readonly report = signal<ImpactReport | null>(null);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  /** Direct uses first, then by depth. */
  readonly affected = computed(() =>
    [...(this.report()?.affected ?? [])].sort((a, b) => a.depth - b.depth || a.from_label.localeCompare(b.from_label)),
  );

  constructor() {
    effect(() => {
      const entity = this.entity();
      const attribute = this.attribute();
      const change = this.change();
      untracked(() => this.load(entity, attribute, change));
    });
  }

  private load(entity: string, attribute: string | null, change: ImpactChange): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.impact(entity, attribute, change).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: r => { this.report.set(r); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }
}
