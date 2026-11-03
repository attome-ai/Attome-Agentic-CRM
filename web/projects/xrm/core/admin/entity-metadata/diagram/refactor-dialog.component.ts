import { ChangeDetectionStrategy, Component, input, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, SdkService, TranslatePipe } from '@attome/base';

export type RefactorKind = 'split' | 'extract_child' | 'to_many_to_many';

/** What a split would do (`SplitPreview`). */
export interface SplitPreview {
  rows_read: number;
  rows_changed: number;
  rows_unconvertible: number;
  more_rows: boolean;
  examples: { id: string; source: string; values: Record<string, string | null> }[];
}

/** An object a refactor leaves for a person to move (`ToReview`). */
export interface ToReview {
  kind: string;
  id: string;
  label: string;
  attribute: string;
}

/**
 * `field = expression` lines as split targets; a line without `=` is left
 * out. Pure.
 */
export function splitTargets(text: string): { field: string; expression: string }[] {
  return text
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.includes('='))
    .map(line => {
      const at = line.indexOf('=');
      return { field: line.slice(0, at).trim(), expression: line.slice(at + 1).trim() };
    })
    .filter(t => t.field && t.expression);
}

/**
 * A1-T14 step 4 — the designer's refactor dialog over A1-T8 and A1-T9's
 * routes: split a text field into several (preview first, then queue), move
 * repeating fields into a child entity, or turn a lookup into a
 * many-to-many relationship. A queued refactor runs as a data step run and
 * lists the forms, views, rules and flows to move by hand. In a Develop
 * workspace (the tab's `X-Attome-Workspace`) it runs there.
 */
@Component({
  selector: 'xrm-refactor-dialog',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styles: [`
    .rf { display: grid; gap: .5rem; padding: .75rem; border: 1px solid var(--color-border, currentColor); border-radius: 6px; }
    .rf textarea { inline-size: 100%; min-block-size: 4rem; }
    .rf-row { display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }
  `],
  template: `
    <section class="rf" data-testid="refactor-dialog">
      <h3>{{ 'dataModel.refactorTitle' | translate }}</h3>
      <label>
        {{ 'dataModel.refactorKind' | translate }}
        <select data-testid="rf-kind" [ngModel]="kind()" (ngModelChange)="kind.set($event)">
          <option value="split">{{ 'dataModel.refactor_split' | translate }}</option>
          <option value="extract_child">{{ 'dataModel.refactor_extract_child' | translate }}</option>
          <option value="to_many_to_many">{{ 'dataModel.refactor_to_many_to_many' | translate }}</option>
        </select>
      </label>
      @switch (kind()) {
        @case ('split') {
          <label>{{ 'dataModel.refactorSource' | translate }}
            <select data-testid="rf-source" [ngModel]="source()" (ngModelChange)="source.set($event)">
              @for (a of attributes(); track a) { <option [value]="a">{{ a }}</option> }
            </select>
          </label>
          <label>{{ 'dataModel.refactorTargets' | translate }}
            <textarea data-testid="rf-targets" [ngModel]="targets()" (ngModelChange)="targets.set($event)"
                      placeholder="first_name = word(full_name, 1)"></textarea>
          </label>
          <div class="rf-row">
            <button type="button" data-testid="rf-preview" (click)="previewSplit()" [disabled]="busy()">
              {{ 'dataModel.refactorPreview' | translate }}</button>
            <button type="button" data-testid="rf-run" (click)="run()" [disabled]="busy() || !preview()">
              {{ 'dataModel.refactorRun' | translate }}</button>
          </div>
          @if (preview(); as p) {
            <p data-testid="rf-preview-result">{{ 'dataModel.refactorWould' | translate: { changed: p.rows_changed, failed: p.rows_unconvertible, read: p.rows_read } }}</p>
          }
        }
        @case ('extract_child') {
          <label>{{ 'dataModel.refactorSources' | translate }}
            <input data-testid="rf-sources" [ngModel]="sources()" (ngModelChange)="sources.set($event)" placeholder="phone_1, phone_2" />
          </label>
          <label>{{ 'dataModel.refactorChild' | translate }}
            <input data-testid="rf-child" [ngModel]="childName()" (ngModelChange)="childName.set($event)" placeholder="contact_phone" />
          </label>
          <button type="button" data-testid="rf-run" (click)="run()" [disabled]="busy()">{{ 'dataModel.refactorRun' | translate }}</button>
        }
        @case ('to_many_to_many') {
          <label>{{ 'dataModel.refactorLookup' | translate }}
            <select data-testid="rf-lookup" [ngModel]="source()" (ngModelChange)="source.set($event)">
              @for (a of attributes(); track a) { <option [value]="a">{{ a }}</option> }
            </select>
          </label>
          <label>{{ 'dataModel.refactorRelationship' | translate }}
            <input data-testid="rf-name" [ngModel]="childName()" (ngModelChange)="childName.set($event)" placeholder="contact_account" />
          </label>
          <button type="button" data-testid="rf-run" (click)="run()" [disabled]="busy()">{{ 'dataModel.refactorRun' | translate }}</button>
        }
      }
      @if (error(); as e) { <p role="alert">{{ e }}</p> }
      @if (queued(); as q) {
        <p data-testid="rf-queued" aria-live="polite">{{ 'dataModel.refactorQueued' | translate: { run: q } }}</p>
      }
      @if (toReview().length) {
        <h4>{{ 'dataModel.refactorReview' | translate }}</h4>
        <ul data-testid="rf-review">
          @for (r of toReview(); track r.kind + r.id) { <li>{{ r.label }} ({{ r.kind }}, {{ r.attribute }})</li> }
        </ul>
      }
    </section>
  `,
})
export class RefactorDialogComponent {
  private readonly sdk = inject(SdkService);

  readonly entityId = input.required<string>();
  readonly entityName = input<string>('');
  /** The entity's attribute logical names. */
  readonly attributes = input<readonly string[]>([]);

  readonly kind = signal<RefactorKind>('split');
  readonly source = signal('');
  readonly targets = signal('');
  readonly sources = signal('');
  readonly childName = signal('');
  readonly preview = signal<SplitPreview | null>(null);
  readonly queued = signal<string | null>(null);
  readonly toReview = signal<ToReview[]>([]);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  private base(): string {
    return `/api/v1/admin/entities/${this.entityId()}/refactor`;
  }

  private splitBody(): { source: string; targets: { field: string; expression: string }[] } {
    return { source: this.source() || this.attributes()[0] || '', targets: splitTargets(this.targets()) };
  }

  previewSplit(): void {
    this.busy.set(true);
    this.error.set(null);
    this.sdk.post<SplitPreview>(`${this.base()}/preview`, { body: this.splitBody() }).subscribe({
      next: p => { this.busy.set(false); this.preview.set(p); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  run(): void {
    const kind = this.kind();
    let path: string;
    let body: unknown;
    if (kind === 'split') {
      path = this.base();
      body = this.splitBody();
    } else if (kind === 'extract_child') {
      path = `${this.base()}/extract-child`;
      body = {
        sources: this.sources().split(',').map(s => s.trim()).filter(Boolean),
        child_logicalname: this.childName().trim(),
        child_name: this.childName().trim(),
      };
    } else {
      path = `${this.base()}/to-many-to-many`;
      body = {
        lookup: this.source() || this.attributes()[0] || '',
        name: this.childName().trim(),
        role_a: this.entityName(),
        role_b: this.source(),
      };
    }
    this.busy.set(true);
    this.error.set(null);
    this.sdk.post<{ run_id: string; to_review?: ToReview[] }>(path, { body }).subscribe({
      next: r => {
        this.busy.set(false);
        this.queued.set(r.run_id);
        this.toReview.set(r.to_review ?? []);
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
