import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

import { CustomerTestEditorComponent } from './customer-test-editor.component';
import type { CustomerTest, CustomerTestRunAll, CustomerTestRunResult } from './customer-test.model';

/**
 * Customer tests (roadmap Z15-T15): a builder's own given/when/expect
 * checks of their configuration. List them with each one's latest result,
 * write or change one, run one or all and read the failures. A run is
 * always rolled back: it never leaves records behind. Logical CSS only.
 */
@Component({
  selector: 'xrm-customer-test-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CustomerTestEditorComponent, LocalDatePipe, TranslatePipe],
  template: `
    <section class="ct">
      <h3>{{ 'customerTestsPage.title' | translate }}</h3>
      <p class="ct-muted">{{ 'customerTestsPage.intro' | translate }}</p>
      @if (error(); as message) { <p class="ct-error" role="alert">{{ message }}</p> }

      @if (editing(); as target) {
        <xrm-customer-test-editor [test]="target === 'new' ? null : target"
                                  (saved)="onSaved()" (cancelled)="editing.set(null)" />
      } @else {
        <div class="ct-toolbar">
          <button type="button" (click)="editing.set('new')">{{ 'customerTestsPage.new' | translate }}</button>
          <button type="button" (click)="runAll()" [disabled]="busy() || tests().length === 0">
            {{ 'customerTestsPage.runAll' | translate }}
          </button>
        </div>

        @if (summary(); as s) {
          <p class="ct-summary" role="status">
            {{ 'customerTestsPage.summary' | translate: { passed: s.passed, failed: s.failed } }}
          </p>
        }

        @if (tests().length === 0) {
          <p class="ct-muted">{{ 'customerTestsPage.none' | translate }}</p>
        } @else {
          <table class="ct-table">
            <thead>
              <tr>
                <th scope="col">{{ 'customerTestsPage.name' | translate }}</th>
                <th scope="col">{{ 'customerTestsPage.lastResult' | translate }}</th>
                <th scope="col">{{ 'customerTestsPage.lastRun' | translate }}</th>
                <th scope="col"><span class="ct-sr">{{ 'customerTestsPage.actions' | translate }}</span></th>
              </tr>
            </thead>
            <tbody>
              @for (t of tests(); track t.id) {
                <tr [attr.data-test]="t.id" [class.ct-inactive]="!t.is_active">
                  <td>
                    {{ t.name }}
                    @if (t.blocking) { <span class="ct-badge">{{ 'customerTestsPage.blocking' | translate }}</span> }
                    @if (!t.is_active) { <span class="ct-badge">{{ 'customerTestsPage.inactive' | translate }}</span> }
                    @if (t.description) { <div class="ct-muted">{{ t.description }}</div> }
                  </td>
                  <td>
                    @switch (t.last_passed) {
                      @case (true) { <span class="ct-pass">{{ 'customerTestsPage.passed' | translate }}</span> }
                      @case (false) { <span class="ct-fail">{{ 'customerTestsPage.failed' | translate }}</span> }
                      @default { <span class="ct-muted">{{ 'customerTestsPage.notRun' | translate }}</span> }
                    }
                  </td>
                  <td>{{ t.last_run_at ? (t.last_run_at | localDate) : '' }}</td>
                  <td class="ct-actions">
                    <button type="button" (click)="run(t)" [disabled]="busy() || !t.is_active">
                      {{ 'customerTestsPage.run' | translate }}
                    </button>
                    <button type="button" (click)="editing.set(t)">{{ 'customerTestsPage.edit' | translate }}</button>
                    <button type="button" (click)="remove(t)" [disabled]="busy()">
                      {{ 'customerTestsPage.delete' | translate }}
                    </button>
                  </td>
                </tr>
                @if (resultOf(t.id); as r) {
                  <tr class="ct-result"><td colspan="4">
                    @for (f of r.failures; track $index) {
                      <div class="ct-fail" dir="auto">{{ f }}</div>
                    } @empty {
                      <div class="ct-pass">{{ 'customerTestsPage.passed' | translate }}</div>
                    }
                  </td></tr>
                }
              }
            </tbody>
          </table>
        }
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .ct { display: flex; flex-direction: column; gap: 0.5rem; }
    .ct h3 { margin-block: 0; font-size: 1rem; }
    .ct-toolbar { display: flex; gap: 0.5rem; }
    .ct-table { inline-size: 100%; border-collapse: collapse; font-size: 0.875rem; }
    .ct-table th, .ct-table td { text-align: start; padding-block: 0.25rem; padding-inline: 0.5rem;
      border-block-end: 1px solid var(--color-border); vertical-align: top; }
    .ct-inactive td { color: var(--color-text-secondary); }
    .ct-badge { margin-inline-start: 0.375rem; font-size: 0.75rem; color: var(--color-text-secondary); }
    .ct-actions { display: flex; flex-wrap: wrap; gap: 0.25rem; }
    .ct-result td { background: var(--color-bg-alt); font-size: 0.8125rem; }
    .ct-pass { color: var(--color-success); }
    .ct-fail { color: var(--color-danger); }
    .ct-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .ct-error { color: var(--color-danger); }
    .ct-sr { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip-path: inset(50%); }
  `],
})
export class CustomerTestListComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly tests = signal<CustomerTest[]>([]);
  readonly results = signal<Record<string, CustomerTestRunResult>>({});
  readonly summary = signal<CustomerTestRunAll | null>(null);
  readonly editing = signal<CustomerTest | 'new' | null>(null);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.getAllPages<CustomerTest>('/api/v1/admin/customer-tests').subscribe({
      next: tests => this.tests.set(tests),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  resultOf(id: string): CustomerTestRunResult | undefined {
    return this.results()[id];
  }

  onSaved(): void {
    this.editing.set(null);
    this.load();
  }

  run(test: CustomerTest): void {
    this.busy.set(true);
    this.error.set(null);
    this.api.post<CustomerTestRunResult>(`/api/v1/admin/customer-tests/${test.id}/run`, null).subscribe({
      next: result => {
        this.busy.set(false);
        this.results.update(all => ({ ...all, [test.id]: result }));
        this.load();
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  runAll(): void {
    this.busy.set(true);
    this.error.set(null);
    this.api.post<CustomerTestRunAll>('/api/v1/admin/customer-tests/run-all', null).subscribe({
      next: all => {
        this.busy.set(false);
        this.summary.set(all);
        this.results.set(Object.fromEntries(all.results.map(r => [r.test_id, r])));
        this.load();
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  remove(test: CustomerTest): void {
    this.busy.set(true);
    this.api.delete(`/api/v1/admin/customer-tests/${test.id}`).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
