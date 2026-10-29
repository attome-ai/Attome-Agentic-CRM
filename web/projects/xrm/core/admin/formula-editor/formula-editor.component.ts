import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal, untracked } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import { ExpressionEditorComponent } from '@attome/xrm/core/admin/expression-editor';

/** How many lookups a formula computed when read may follow (the server's
 * `attome_core::formula::MAX_FORMULA_HOPS`). */
export const FORMULA_LOOKUP_HOPS = 5;

/** `stored`: computed on every write, from the record's own fields;
 * `read_time`: computed whenever the record is read, and may read through lookups. */
export type FormulaMode = 'stored' | 'read_time';

/** What a save sends and what it was saved for. */
export interface FormulaSave { fieldId: string; options: Record<string, unknown>; }

/** A formula field's `options` with a new expression and mode, keeping the
 * rest (its result type, `generated`). Pure. */
export function formulaOptions(current: unknown, expression: string, mode: FormulaMode): Record<string, unknown> {
  const base = current && typeof current === 'object' ? { ...(current as Record<string, unknown>) } : {};
  return { ...base, expression, mode };
}

/**
 * A9-T4: writes a formula field's expression. The shared expression editor
 * completes the entity's fields and functions, and, for a formula computed
 * when read, field paths through lookups; its preview runs the expression
 * on a sample record through `POST /api/v1/admin/expressions/validate`.
 * Saving sends the options with `PATCH /api/v1/admin/entities/{id}/fields/{field}`,
 * where the server compiles the formula again and refuses one that does not
 * fit (its message is shown).
 */
@Component({
  selector: 'xrm-formula-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ExpressionEditorComponent, TranslatePipe],
  template: `
    <section class="fe" data-testid="formula-editor" [attr.aria-label]="'formulaEditor.title' | translate: { field: fieldName() }">
      <fieldset class="fe-mode">
        <legend>{{ 'formulaEditor.mode' | translate }}</legend>
        <label>
          <input type="radio" name="fe-mode-{{ fieldId() }}" value="stored" [checked]="mode() === 'stored'"
                 [disabled]="generated()" (change)="mode.set('stored')" data-testid="formula-mode-stored" />
          {{ 'formulaEditor.stored' | translate }}
        </label>
        <label>
          <input type="radio" name="fe-mode-{{ fieldId() }}" value="read_time" [checked]="mode() === 'read_time'"
                 [disabled]="generated()" (change)="mode.set('read_time')" data-testid="formula-mode-read-time" />
          {{ 'formulaEditor.readTime' | translate }}
        </label>
      </fieldset>
      <p class="fe-hint">
        {{ (mode() === 'read_time' ? 'formulaEditor.readTimeHint' : 'formulaEditor.storedHint') | translate: { hops: hops } }}
      </p>
      @if (resultType(); as type) {
        <p class="fe-hint">{{ 'formulaEditor.resultType' | translate: { type } }}</p>
      }
      <xrm-expression-editor [entity]="entity()" [(value)]="expression" [lookupHops]="lookupHops()"
                             [label]="'formulaEditor.expression' | translate" [rows]="4" />
      @if (error(); as message) {
        <p class="fe-error" role="alert" data-testid="formula-error">{{ message }}</p>
      }
      <div class="fe-actions">
        <button type="button" class="btn btn-primary" data-testid="formula-save"
                [disabled]="saving() || !expression().trim() || !changed()" (click)="save()">
          {{ 'formulaEditor.save' | translate }}
        </button>
        <button type="button" class="btn btn-secondary" (click)="cancelled.emit()">
          {{ 'formulaEditor.cancel' | translate }}
        </button>
      </div>
    </section>
  `,
  styles: [`
    .fe { display: flex; flex-direction: column; gap: .5rem; padding-block: .5rem; }
    .fe-mode { display: flex; gap: 1rem; border: 0; padding: 0; margin: 0; }
    .fe-mode legend { font-weight: 600; padding: 0; margin-block-end: .25rem; }
    .fe-hint { color: var(--color-text-secondary); font-size: .8125rem; margin: 0; }
    .fe-error { color: var(--color-danger); margin: 0; }
    .fe-actions { display: flex; gap: .5rem; }
  `],
})
export class FormulaEditorComponent {
  private readonly admin = inject(AdminService);
  private readonly lang = inject(LangService);

  /** The entity's id, for the save route. */
  readonly entityId = input.required<string>();
  /** The entity's logical name, whose fields the formula reads. */
  readonly entity = input.required<string>();
  /** The formula field's id. */
  readonly fieldId = input.required<string>();
  readonly fieldName = input('');
  /** The field's current `options` (`expression`, `result_type`, `mode`, `generated`). */
  readonly options = input<unknown>(null);

  readonly saved = output<FormulaSave>();
  readonly cancelled = output<void>();

  protected readonly hops = FORMULA_LOOKUP_HOPS;
  readonly expression = signal('');
  readonly mode = signal<FormulaMode>('stored');
  readonly saving = signal(false);
  readonly error = signal<string | null>(null);

  private readonly current = computed(() => {
    const o = this.options() as { expression?: unknown; mode?: unknown; result_type?: unknown; generated?: unknown } | null;
    return {
      expression: typeof o?.expression === 'string' ? o.expression : '',
      mode: (o?.mode === 'read_time' ? 'read_time' : 'stored') as FormulaMode,
      resultType: typeof o?.result_type === 'string' ? o.result_type : null,
      generated: o?.generated === true,
    };
  });
  readonly resultType = computed(() => this.current().resultType);
  /** A database-generated formula stays stored (Y2-T11). */
  readonly generated = computed(() => this.current().generated);
  /** Paths through lookups only for a formula computed when read. */
  readonly lookupHops = computed(() => (this.mode() === 'read_time' ? FORMULA_LOOKUP_HOPS : 0));
  readonly changed = computed(() =>
    this.expression() !== this.current().expression || this.mode() !== this.current().mode);

  constructor() {
    effect(() => {
      const c = this.current();
      untracked(() => {
        this.expression.set(c.expression);
        this.mode.set(c.mode);
        this.error.set(null);
      });
    });
  }

  save(): void {
    const options = formulaOptions(this.options(), this.expression(), this.mode());
    this.saving.set(true);
    this.error.set(null);
    this.admin.updateAttribute(this.entityId(), this.fieldId(), { options }).subscribe({
      next: () => {
        this.saving.set(false);
        this.saved.emit({ fieldId: this.fieldId(), options });
      },
      error: (e: ApiError) => {
        this.saving.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}
