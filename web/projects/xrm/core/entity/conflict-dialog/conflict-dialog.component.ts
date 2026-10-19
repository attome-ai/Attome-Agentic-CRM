import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal } from '@angular/core';
import { LangService, TranslatePipe, VersionConflictState } from '@attome/base';

/** Per attribute: keep the value typed here, or take the other writer's. */
export type ConflictChoice = 'mine' | 'theirs';
export type ConflictChoices = Record<string, ConflictChoice>;

/** One row of the dialog. */
interface ConflictRow {
  name: string;
  label: string;
  mine: string;
  theirs: string;
  by: string | null;
  at: string;
}

/**
 * A16-T3: a save refused because someone else changed the record since it
 * was loaded. Lists each attribute they changed, with the value typed here
 * and theirs (who, when), and asks per attribute: keep mine or take theirs
 * ("keep mine" by default). Confirming answers `resolve` with the choices;
 * cancelling answers `cancelled`. Neither touches the values on screen: the
 * form decides. Changes to fields this person may not read are only counted.
 */
@Component({
  selector: 'xrm-conflict-dialog',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./conflict-dialog.component.css'],
  template: `
    <section class="conflict-dialog" role="dialog" aria-modal="false" aria-labelledby="conflict-dialog-title"
             data-conflict-dialog>
      <h3 id="conflict-dialog-title">{{ 'conflictDialog.title' | translate }}</h3>
      <p class="conflict-intro">{{ 'conflictDialog.intro' | translate }}</p>
      <div class="table-wrap">
        <table class="conflict-table">
          <thead>
            <tr>
              <th scope="col">{{ 'conflictDialog.field' | translate }}</th>
              <th scope="col">{{ 'conflictDialog.yours' | translate }}</th>
              <th scope="col">{{ 'conflictDialog.theirs' | translate }}</th>
            </tr>
          </thead>
          <tbody>
            @for (row of rows(); track row.name) {
              <tr [attr.data-conflict-row]="row.name">
                <th scope="row">{{ row.label }}</th>
                <td>
                  <label class="conflict-pick">
                    <input type="radio" [name]="'conflict-' + row.name" [attr.data-conflict-pick]="row.name + ':mine'"
                           [checked]="choices()[row.name] !== 'theirs'" (change)="pick(row.name, 'mine')" />
                    <span>{{ row.mine }}</span>
                  </label>
                </td>
                <td>
                  <label class="conflict-pick">
                    <input type="radio" [name]="'conflict-' + row.name" [attr.data-conflict-pick]="row.name + ':theirs'"
                           [checked]="choices()[row.name] === 'theirs'" (change)="pick(row.name, 'theirs')" />
                    <span>{{ row.theirs }}</span>
                  </label>
                  <span class="conflict-who">
                    @if (row.by) {
                      {{ 'conflictDialog.changedBy' | translate: { name: row.by, time: row.at } }}
                    } @else if (row.at) {
                      {{ 'conflictDialog.changedAt' | translate: { time: row.at } }}
                    }
                  </span>
                </td>
              </tr>
            }
          </tbody>
        </table>
      </div>
      @if (details().hiddenChanges > 0) {
        <p class="conflict-hidden" data-conflict-hidden>
          {{ 'conflictDialog.hidden' | translate: { count: details().hiddenChanges } }}
        </p>
      }
      <div class="conflict-actions">
        <button type="button" class="xf-btn xf-btn-primary" data-conflict-confirm (click)="confirm()">
          {{ 'conflictDialog.confirm' | translate }}
        </button>
        <button type="button" class="xf-btn xf-btn-secondary" data-conflict-cancel (click)="cancelled.emit()">
          {{ 'conflictDialog.cancel' | translate }}
        </button>
      </div>
    </section>
  `,
})
export class ConflictDialogComponent {
  private readonly lang = inject(LangService);

  /** What the 409 said changed. */
  readonly details = input.required<VersionConflictState>();
  /** The values on the form now. */
  readonly mine = input<Readonly<Record<string, unknown>>>({});
  /** The display name of an attribute. */
  readonly labelOf = input<(name: string) => string>(name => name);

  /** Confirmed, with a choice for every listed attribute. */
  readonly resolve = output<ConflictChoices>();
  /** Closed without saving; the typed values stay as they are. */
  readonly cancelled = output<void>();

  readonly choices = signal<ConflictChoices>({});

  readonly rows = computed<ConflictRow[]>(() => {
    const mine = this.mine();
    const label = this.labelOf();
    return this.details().changedAttributes.map(change => ({
      name: change.name,
      label: label(change.name),
      mine: this.show(mine[change.name]),
      theirs: this.show(change.their_value),
      by: change.changed_by,
      at: this.time(change.changed_at),
    }));
  });

  constructor() {
    // A new conflict starts again from "keep mine" for every attribute.
    effect(() => {
      const names = this.details().changedAttributes.map(change => change.name);
      this.choices.set(Object.fromEntries(names.map(name => [name, 'mine' as ConflictChoice])));
    });
  }

  pick(name: string, choice: ConflictChoice): void {
    this.choices.update(current => ({ ...current, [name]: choice }));
  }

  confirm(): void {
    this.resolve.emit({ ...this.choices() });
  }

  private show(value: unknown): string {
    if (value === null || value === undefined || value === '') return this.lang.translate('conflictDialog.empty');
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  }

  private time(at: string | null): string {
    if (!at) return '';
    const date = new Date(at);
    return Number.isNaN(date.getTime())
      ? ''
      : new Intl.DateTimeFormat(this.lang.intlLocale(), { dateStyle: 'short', timeStyle: 'short' }).format(date);
  }
}
