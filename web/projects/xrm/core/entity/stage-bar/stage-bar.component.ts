import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

/** One stage of a stage process (`attome_model::kinds::stage_process`). */
export interface ProcessStage {
  code: string;
  label_en: string;
  label_ar?: string;
  required?: string[];
  checklist?: string[];
  next?: string[];
}

/** `attome_api::stage_process_api::StageProcessView`. */
export interface StageProcessView {
  id: string;
  name: string;
  entity: string;
  stages: ProcessStage[];
}

/** The required attributes of `stage` that `values` leaves empty. */
export function missingFor(stage: ProcessStage, values: Readonly<Record<string, unknown>>): string[] {
  return (stage.required ?? []).filter(attribute => {
    const value = values[attribute];
    return value === null || value === undefined
      || (typeof value === 'string' && value.trim() === '')
      || (Array.isArray(value) && value.length === 0);
  });
}

/**
 * The stage bar on a record form (roadmap M7-T2): the entity's stages in
 * order with the current one marked, the current stage's checklist, and a
 * button for each stage it may move to next. A stage whose required
 * attributes are still empty names them and cannot be chosen; choosing one
 * sets the form's stage, and saving the form makes the move, which the
 * server checks again. Renders nothing for an entity without a published
 * stage process.
 */
@Component({
  selector: 'xrm-stage-bar',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (process(); as p) {
      <nav class="sb" [attr.aria-label]="'stageBar.label' | translate">
        <ol class="sb-stages">
          @for (s of p.stages; track s.code) {
            <li class="sb-stage" [class.sb-current]="s.code === current()" [class.sb-done]="isPast(s.code)"
                [attr.aria-current]="s.code === current() ? 'step' : null" [attr.data-stage]="s.code">
              {{ labelOf(s) }}
            </li>
          }
        </ol>
        @if (currentStage(); as c) {
          @if ((c.checklist ?? []).length > 0) {
            <ul class="sb-checklist" [attr.aria-label]="'stageBar.checklist' | translate">
              @for (item of c.checklist; track item) { <li dir="auto">{{ item }}</li> }
            </ul>
          }
        }
        <div class="sb-next">
          @for (n of nextStages(); track n.stage.code) {
            <div class="sb-option" [attr.data-next]="n.stage.code">
              <button type="button" class="sb-move" [disabled]="n.missing.length > 0 || disabled()" (click)="choose.emit(n.stage.code)">
                {{ 'stageBar.moveTo' | translate: { stage: labelOf(n.stage) } }}
              </button>
              @if (n.missing.length > 0) {
                <span class="sb-missing">{{ 'stageBar.missing' | translate: { fields: n.missing.join(', ') } }}</span>
              }
            </div>
          }
        </div>
      </nav>
    }
    @if (error(); as message) { <p class="sb-error" role="alert">{{ message }}</p> }
  `,
  styles: [`
    :host { display: block; }
    .sb { display: flex; flex-direction: column; gap: 0.375rem; margin-block: 0.5rem; }
    .sb-stages { display: flex; flex-wrap: wrap; gap: 0.25rem; list-style: none; margin: 0; padding: 0; }
    .sb-stage { padding-block: 0.25rem; padding-inline: 0.75rem; border: 1px solid var(--color-border);
      border-radius: 999px; font-size: 0.8125rem; color: var(--color-text-secondary); }
    .sb-done { color: inherit; }
    .sb-current { font-weight: 600; color: inherit; border-color: currentColor; }
    .sb-checklist { margin: 0; padding-inline-start: 1.25rem; font-size: 0.8125rem; }
    .sb-next { display: flex; flex-wrap: wrap; gap: 0.5rem; }
    .sb-option { display: flex; flex-direction: column; gap: 0.125rem; }
    .sb-missing { font-size: 0.75rem; color: var(--color-text-secondary); }
    .sb-error { color: var(--color-danger); font-size: 0.8125rem; }
  `],
})
export class StageBarComponent {
  private readonly api = inject(ApiService);

  readonly entityName = input.required<string>();
  /** The record's values as the form holds them now. */
  readonly values = input<Readonly<Record<string, unknown>>>({});
  /** Arabic labels when the interface is in Arabic. */
  readonly arabic = input(false);
  readonly disabled = input(false);
  /** A next stage was chosen; the form sets its stage and the save moves it. */
  readonly choose = output<string>();

  readonly process = signal<StageProcessView | null>(null);
  readonly error = signal<string | null>(null);

  readonly current = computed(() => {
    const stage = this.values()['stage'];
    return typeof stage === 'string' && stage ? stage : this.process()?.stages[0]?.code ?? null;
  });
  readonly currentStage = computed(() => this.process()?.stages.find(s => s.code === this.current()) ?? null);
  readonly nextStages = computed(() => {
    const p = this.process();
    const c = this.currentStage();
    if (!p || !c) return [];
    const values = this.values();
    return (c.next ?? [])
      .map(code => p.stages.find(s => s.code === code))
      .filter((s): s is ProcessStage => !!s)
      .map(stage => ({ stage, missing: missingFor(stage, values) }));
  });

  constructor() {
    effect(() => {
      const entity = this.entityName();
      this.error.set(null);
      this.api.get<StageProcessView>(`/api/v1/stage-processes/for/${encodeURIComponent(entity)}`).subscribe({
        next: p => this.process.set(p),
        error: (e: ApiError) => {
          this.process.set(null);
          if (e.status !== 404) this.error.set(e.message);
        },
      });
    });
  }

  labelOf(stage: ProcessStage): string {
    return this.arabic() && stage.label_ar ? stage.label_ar : stage.label_en;
  }

  isPast(code: string): boolean {
    const stages = this.process()?.stages ?? [];
    const at = stages.findIndex(s => s.code === this.current());
    const index = stages.findIndex(s => s.code === code);
    return index >= 0 && at >= 0 && index < at;
  }
}
