import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  DataQualityService, RULE_DIMENSIONS, RULE_SEVERITIES, type QualityRule,
} from '@attome/xrm/core/admin/data';

/** The rule being written: a new one, or an edit of `id`. */
interface RuleDraft {
  id: string | null;
  rowVersion: number;
  entity: string;
  attribute: string;
  dimension: string;
  expression: string;
  severity: string;
  weight: number;
  enabled: boolean;
}

const EMPTY: RuleDraft = {
  id: null, rowVersion: 0, entity: '', attribute: '', dimension: 'validity',
  expression: '', severity: 'warning', weight: 1, enabled: true,
};

/**
 * L2-T8: the Rules tab of the data-quality screen. Validity and consistency
 * rules are conditions each record must hold (`amount >= 0`), checked by the
 * quality sweep; the server parses the condition, so a wrong one comes back
 * as its own error.
 */
@Component({
  selector: 'xrm-quality-rules',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalNumberPipe, TranslatePipe],
  styleUrls: ['../../../../styles/admin-page.css', '../governance.css', './data-quality.component.css'],
  template: `
    <section class="card" aria-labelledby="dq-rules-title">
      <div class="section-header">
        <h3 id="dq-rules-title">{{ 'governance.quality.rules.title' | translate }}</h3>
        <button type="button" class="btn-sm" data-rule-new (click)="startNew()">
          <i class="las la-plus" aria-hidden="true"></i> {{ 'governance.quality.rules.new' | translate }}
        </button>
      </div>

      @if (draft(); as d) {
        <form class="dq-rule-form" (ngSubmit)="save()" data-rule-form>
          <label>{{ 'governance.common.entity' | translate }}
            <input class="mono-input" name="entity" [(ngModel)]="d.entity" [disabled]="!!d.id" required />
          </label>
          <label>{{ 'governance.quality.field' | translate }}
            <input class="mono-input" name="attribute" [(ngModel)]="d.attribute" [disabled]="!!d.id" />
          </label>
          <label>{{ 'governance.quality.dimension' | translate }}
            <select name="dimension" [(ngModel)]="d.dimension" [disabled]="!!d.id">
              @for (dim of ruleDimensions; track dim) {
                <option [value]="dim">{{ 'governance.quality.dimensions.' + dim | translate }}</option>
              }
            </select>
          </label>
          <label class="dq-rule-form__wide">{{ 'governance.quality.rules.expression' | translate }}
            <textarea class="mono-input" name="expression" rows="2" [(ngModel)]="d.expression" required
                      [placeholder]="'governance.quality.rules.expressionHint' | translate"></textarea>
          </label>
          <label>{{ 'governance.quality.rules.severity' | translate }}
            <select name="severity" [(ngModel)]="d.severity">
              @for (sev of severities; track sev) {
                <option [value]="sev">{{ 'governance.quality.rules.severities.' + sev | translate }}</option>
              }
            </select>
          </label>
          <label>{{ 'governance.quality.rules.weight' | translate }}
            <input type="number" name="weight" min="0" step="0.5" [(ngModel)]="d.weight" />
          </label>
          <label class="dq-check"><input type="checkbox" name="enabled" [(ngModel)]="d.enabled" />
            {{ 'governance.quality.rules.enabled' | translate }}</label>
          @if (formError(); as message) { <p class="error-msg" role="alert">{{ message | translate }}</p> }
          <div class="dq-rule-form__actions">
            <button type="submit" class="btn-primary" [disabled]="saving() || !d.entity.trim() || !d.expression.trim()">
              {{ 'governance.quality.rules.save' | translate }}
            </button>
            <button type="button" class="btn-ghost" (click)="cancel()">{{ 'governance.quality.rules.cancel' | translate }}</button>
          </div>
        </form>
      }

      @if (loading()) {
        <p class="state-msg">{{ 'governance.common.loading' | translate }}</p>
      } @else if (error()) {
        <p class="error-msg" role="alert">{{ error() }}</p>
      } @else if (rules().length === 0) {
        <div class="empty-state"><p>{{ 'governance.quality.rules.none' | translate }}</p></div>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{{ 'governance.common.entity' | translate }}</th>
                <th scope="col">{{ 'governance.quality.field' | translate }}</th>
                <th scope="col">{{ 'governance.quality.dimension' | translate }}</th>
                <th scope="col">{{ 'governance.quality.rules.expression' | translate }}</th>
                <th scope="col">{{ 'governance.quality.rules.severity' | translate }}</th>
                <th scope="col">{{ 'governance.quality.rules.weight' | translate }}</th>
                <th scope="col">{{ 'governance.quality.rules.enabled' | translate }}</th>
                <th scope="col"><span class="gov-visually-hidden">{{ 'governance.quality.rules.actions' | translate }}</span></th>
              </tr>
            </thead>
            <tbody>
              @for (r of rules(); track r.id) {
                <tr>
                  <td class="cell-mono">{{ r.entity }}</td>
                  <td class="cell-mono">{{ r.attribute ?? '—' }}</td>
                  <td>{{ 'governance.quality.dimensions.' + r.dimension | translate }}</td>
                  <td class="cell-mono" dir="ltr">{{ r.expression }}</td>
                  <td><span class="badge">{{ 'governance.quality.rules.severities.' + r.severity | translate }}</span></td>
                  <td>{{ r.weight | localNumber: { maximumFractionDigits: 2 } }}</td>
                  <td>{{ (r.enabled ? 'governance.quality.rules.yes' : 'governance.quality.rules.no') | translate }}</td>
                  <td class="actions">
                    <button type="button" class="btn-sm" data-rule-edit (click)="edit(r)">
                      {{ 'governance.quality.rules.edit' | translate }}
                    </button>
                    <button type="button" class="btn-sm" data-rule-delete (click)="remove(r)" [disabled]="saving()">
                      {{ 'governance.quality.rules.delete' | translate }}
                    </button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </section>
  `,
})
export class QualityRulesComponent implements OnInit {
  private readonly svc = inject(DataQualityService);
  private readonly destroyRef = inject(DestroyRef);

  /** The entity filter of the screen; empty for every entity. */
  readonly entity = input('');

  readonly ruleDimensions = RULE_DIMENSIONS;
  readonly severities = RULE_SEVERITIES;

  readonly rules = signal<QualityRule[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly draft = signal<RuleDraft | null>(null);
  readonly saving = signal(false);
  readonly formError = signal<string | null>(null);

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.listRules(this.entity().trim() || undefined).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: items => { this.rules.set(items); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  startNew(): void {
    this.formError.set(null);
    this.draft.set({ ...EMPTY, entity: this.entity().trim() });
  }

  edit(rule: QualityRule): void {
    this.formError.set(null);
    this.draft.set({
      id: rule.id, rowVersion: rule.row_version, entity: rule.entity, attribute: rule.attribute ?? '',
      dimension: rule.dimension, expression: rule.expression, severity: rule.severity,
      weight: rule.weight, enabled: rule.enabled,
    });
  }

  cancel(): void {
    this.draft.set(null);
  }

  save(): void {
    const d = this.draft();
    if (!d) return;
    this.saving.set(true);
    this.formError.set(null);
    const done = {
      next: () => { this.saving.set(false); this.draft.set(null); this.load(); },
      error: (e: ApiError) => {
        this.saving.set(false);
        this.formError.set(e.status === 409 ? 'governance.quality.rules.conflict' : e.message);
      },
    };
    if (d.id) {
      this.svc.updateRule(d.id, {
        row_version: d.rowVersion, expression: d.expression.trim(), severity: d.severity,
        weight: Number(d.weight), enabled: d.enabled,
      }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe(done);
    } else {
      this.svc.createRule({
        entity: d.entity.trim(), attribute: d.attribute.trim() || null, dimension: d.dimension,
        expression: d.expression.trim(), severity: d.severity, weight: Number(d.weight), enabled: d.enabled,
      }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe(done);
    }
  }

  remove(rule: QualityRule): void {
    this.saving.set(true);
    this.svc.deleteRule(rule.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => { this.saving.set(false); this.load(); },
      error: (e: ApiError) => { this.saving.set(false); this.error.set(e.message); },
    });
  }
}
