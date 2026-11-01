import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** One acceptance script as `GET /api/v1/acceptance-scripts` lists it. */
export interface AcceptanceScript {
  id: string;
  name: string;
  description?: string | null;
  steps: string[];
  last_passed?: boolean | null;
  last_run_at?: string | null;
}

interface StepState { passed: boolean | null; note: string }

interface ChecklistRunResult { run_id: string; passed: boolean; failures: string[] }

/**
 * T7-T4 — acceptance scripts for business users: the checklists a builder
 * wrote as customer tests. Pick a script, mark each step passed or failed
 * (with a note on a failure) and record the run; the builder sees it beside
 * the automatic runs. Any signed-in user. Logical CSS only.
 */
@Component({
  selector: 'xrm-acceptance-scripts',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  template: `
    <section class="as">
      <h3>{{ 'acceptanceScripts.title' | translate }}</h3>
      <p class="as-muted">{{ 'acceptanceScripts.intro' | translate }}</p>
      @if (error(); as message) { <p class="as-error" role="alert">{{ message }}</p> }

      @if (active(); as script) {
        <h4>{{ script.name }}</h4>
        @if (script.description) { <p class="as-muted" dir="auto">{{ script.description }}</p> }
        <ol class="as-steps" data-testid="as-steps">
          @for (step of script.steps; track $index; let i = $index) {
            <li>
              <span dir="auto">{{ step }}</span>
              <span class="as-marks" role="group" [attr.aria-label]="'acceptanceScripts.markStep' | translate: { n: i + 1 }">
                <button type="button" [attr.aria-pressed]="marks()[i].passed === true" (click)="mark(i, true)">
                  {{ 'acceptanceScripts.pass' | translate }}
                </button>
                <button type="button" [attr.aria-pressed]="marks()[i].passed === false" (click)="mark(i, false)">
                  {{ 'acceptanceScripts.fail' | translate }}
                </button>
              </span>
              @if (marks()[i].passed === false) {
                <input dir="auto" [attr.aria-label]="'acceptanceScripts.note' | translate"
                       [placeholder]="'acceptanceScripts.note' | translate"
                       [value]="marks()[i].note" (input)="note(i, $any($event.target).value)" />
              }
            </li>
          }
        </ol>
        <div class="as-toolbar">
          <button type="button" data-testid="as-record" [disabled]="busy() || !complete()" (click)="record(script)">
            {{ 'acceptanceScripts.record' | translate }}
          </button>
          <button type="button" (click)="close()">{{ 'acceptanceScripts.back' | translate }}</button>
        </div>
        @if (result(); as r) {
          <p role="status" data-testid="as-result" [class.as-pass]="r.passed" [class.as-error]="!r.passed">
            {{ (r.passed ? 'acceptanceScripts.passed' : 'acceptanceScripts.failed') | translate }}
          </p>
          @for (f of r.failures; track $index) { <div dir="auto">{{ f }}</div> }
        }
      } @else if (scripts().length === 0) {
        <p class="as-muted">{{ 'acceptanceScripts.none' | translate }}</p>
      } @else {
        <ul class="as-list" data-testid="as-list">
          @for (s of scripts(); track s.id) {
            <li>
              <button type="button" (click)="open(s)">{{ s.name }}</button>
              <span class="as-muted">
                {{ 'acceptanceScripts.stepCount' | translate: { n: s.steps.length } }}
                @if (s.last_run_at) {
                  · {{ (s.last_passed ? 'acceptanceScripts.passed' : 'acceptanceScripts.failed') | translate }}
                  {{ s.last_run_at | localDate }}
                }
              </span>
            </li>
          }
        </ul>
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .as { display: flex; flex-direction: column; gap: 0.75rem; padding-inline: 1rem; }
    .as-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .as-error { color: var(--color-danger); }
    .as-pass { color: var(--color-success); }
    .as-steps { display: flex; flex-direction: column; gap: 0.5rem; padding-inline-start: 1.25rem; }
    .as-steps li { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
    .as-marks { display: inline-flex; gap: 0.25rem; }
    .as-marks button[aria-pressed='true'] { font-weight: 600; }
    .as-toolbar { display: flex; gap: 0.5rem; }
    .as-list { display: flex; flex-direction: column; gap: 0.5rem; padding-inline-start: 0; list-style: none; }
  `],
})
export class AcceptanceScriptsComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly scripts = signal<AcceptanceScript[]>([]);
  readonly active = signal<AcceptanceScript | null>(null);
  readonly marks = signal<StepState[]>([]);
  readonly result = signal<ChecklistRunResult | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  /** Every step is marked. */
  readonly complete = computed(() => this.marks().length > 0 && this.marks().every(m => m.passed !== null));

  ngOnInit(): void { this.load(); }

  private load(): void {
    this.api.getAllPages<AcceptanceScript>('/api/v1/acceptance-scripts').subscribe({
      next: scripts => this.scripts.set(scripts),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  open(script: AcceptanceScript): void {
    this.active.set(script);
    this.result.set(null);
    this.marks.set(script.steps.map(() => ({ passed: null, note: '' })));
  }

  close(): void {
    this.active.set(null);
    this.load();
  }

  mark(index: number, passed: boolean): void {
    this.marks.update(ms => ms.map((m, i) => (i === index ? { ...m, passed } : m)));
  }

  note(index: number, note: string): void {
    this.marks.update(ms => ms.map((m, i) => (i === index ? { ...m, note } : m)));
  }

  record(script: AcceptanceScript): void {
    this.busy.set(true);
    this.error.set(null);
    const steps = this.marks().map(m => ({ passed: m.passed === true, note: m.note.trim() || null }));
    this.api.post<ChecklistRunResult>(`/api/v1/acceptance-scripts/${script.id}/runs`, { steps }).subscribe({
      next: r => { this.busy.set(false); this.result.set(r); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
