import { ChangeDetectionStrategy, Component, inject, input, signal } from '@angular/core';
import { ApiError, TranslatePipe } from '@attome/base';

import { AffectedTest, ModelService } from '../model.service';

/**
 * T7-T2 — the customer tests a metadata object's publish can affect, run on
 * demand before publishing (`POST /api/v1/admin/model/{kind}/{id}/validate`
 * with `run_tests`). A failing blocking test stops the publish while the
 * deployment requires tests to pass; the others only report.
 */
@Component({
  selector: 'xrm-model-tests-preview',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styles: [`
    :host { display: block; }
    .mtp { display: flex; flex-direction: column; gap: .25rem; font-size: .875rem; }
    .mtp ul { margin: 0; padding-inline-start: 1rem; }
    .mtp-pass { color: var(--color-success); }
    .mtp-fail { color: var(--color-danger); }
    .mtp-muted { color: var(--color-text-secondary); }
  `],
  template: `
    <div class="mtp" data-testid="model-tests-preview">
      <div>
        <button type="button" data-testid="mtp-run" [disabled]="busy()" (click)="run()">
          {{ 'modelTests.run' | translate }}
        </button>
      </div>
      @if (error(); as e) { <p class="mtp-fail" role="alert">{{ e }}</p> }
      @if (results(); as rs) {
        @if (rs.length === 0) {
          <p class="mtp-muted" role="status">{{ 'modelTests.none' | translate }}</p>
        } @else {
          <ul data-testid="mtp-results" role="status">
            @for (r of rs; track r.id) {
              <li [class.mtp-pass]="r.passed" [class.mtp-fail]="!r.passed">
                {{ r.name }} — {{ (r.passed ? 'modelTests.passed' : 'modelTests.failed') | translate }}
                @if (r.blocking) { <span class="mtp-muted">({{ 'modelTests.blocking' | translate }})</span> }
                @for (f of r.failures; track $index) { <div dir="auto">{{ f }}</div> }
              </li>
            }
          </ul>
        }
      }
    </div>
  `,
})
export class ModelTestsPreviewComponent {
  private readonly model = inject(ModelService);

  readonly kind = input.required<string>();
  readonly objectId = input.required<string>();
  /** The document as it would be published. */
  readonly doc = input<unknown>(null);

  readonly results = signal<AffectedTest[] | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  run(): void {
    this.busy.set(true);
    this.error.set(null);
    this.model.previewTests(this.kind(), this.objectId(), this.doc()).subscribe({
      next: tests => { this.busy.set(false); this.results.set(tests); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
