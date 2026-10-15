import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

/** `metadata_label_admin::WorkbenchRow`. */
export interface WorkbenchRow {
  key: string;
  source: string;
  target: string | null;
  status: 'untranslated' | 'stale' | 'draft' | 'reviewed';
}

export const WORKBENCH_STATUSES = ['untranslated', 'stale', 'draft', 'reviewed'] as const;

function xmlEscape(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** One label's translation as the XLIFF 2.0 document the import route reads. */
export function oneUnitXliff(locale: string, row: WorkbenchRow, target: string): string {
  return '<?xml version="1.0" encoding="UTF-8"?>\n'
    + `<xliff xmlns="urn:oasis:names:tc:xliff:document:2.0" version="2.0" srcLang="en" trgLang="${xmlEscape(locale)}">`
    + `<file id="attome-labels"><unit id="${xmlEscape(row.key)}"><segment>`
    + `<source>${xmlEscape(row.source)}</source><target>${xmlEscape(target)}</target>`
    + '</segment></unit></file></xliff>';
}

/**
 * A20-T3: every entity, attribute and choice label with its translation in
 * one language and where it stands (untranslated, stale, draft, reviewed).
 * A translation is edited in place and saved through the XLIFF import, so it
 * gets the same checks (its placeholders, its length) and audit.
 */
@Component({
  selector: 'xrm-label-workbench',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <section class="lw">
      <header class="lw-head">
        <h2>{{ 'labelWorkbench.title' | translate }}</h2>
        <label>
          <span>{{ 'labelWorkbench.language' | translate }}</span>
          <input dir="ltr" class="lw-locale" [ngModel]="locale()" (ngModelChange)="locale.set($event)" (change)="load()" />
        </label>
        <label>
          <span>{{ 'labelWorkbench.show' | translate }}</span>
          <select [ngModel]="status()" (ngModelChange)="status.set($event); load()">
            <option value="">{{ 'labelWorkbench.all' | translate }}</option>
            @for (s of statuses; track s) {
              <option [value]="s">{{ 'labelWorkbench.status.' + s | translate }}</option>
            }
          </select>
        </label>
        <span class="lw-muted">{{ 'labelWorkbench.count' | translate: { count: rows().length } }}</span>
      </header>
      @if (error(); as message) { <p class="lw-error" role="alert">{{ message }}</p> }
      <table class="lw-table">
        <thead>
          <tr>
            <th scope="col">{{ 'labelWorkbench.source' | translate }}</th>
            <th scope="col">{{ 'labelWorkbench.translation' | translate }}</th>
            <th scope="col">{{ 'labelWorkbench.statusHeader' | translate }}</th>
            <th scope="col"><span class="lw-sr">{{ 'labelWorkbench.save' | translate }}</span></th>
          </tr>
        </thead>
        <tbody>
          @for (row of rows(); track row.key) {
            <tr [attr.data-key]="row.key">
              <td>
                <span dir="auto">{{ row.source }}</span>
                <span class="lw-muted lw-key" dir="ltr">{{ row.key }}</span>
              </td>
              <td>
                <input dir="auto" class="lw-input" [ngModel]="draft(row)" (ngModelChange)="edit(row, $event)"
                       [attr.aria-label]="'labelWorkbench.translation' | translate" />
              </td>
              <td><span class="lw-badge" [attr.data-status]="row.status">{{ 'labelWorkbench.status.' + row.status | translate }}</span></td>
              <td>
                <button type="button" class="btn btn-text" [disabled]="!isDirty(row) || busy()" (click)="save(row)">
                  {{ 'labelWorkbench.save' | translate }}
                </button>
              </td>
            </tr>
          }
        </tbody>
      </table>
    </section>
  `,
  styles: [`
    :host { display: block; }
    .lw { display: flex; flex-direction: column; gap: 0.75rem; }
    .lw-head { display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem; }
    .lw-head h2 { margin-block: 0; font-size: 1.25rem; margin-inline-end: auto; }
    .lw-head label { display: flex; align-items: center; gap: 0.5rem; }
    .lw-locale { inline-size: 7rem; }
    .lw-table { border-collapse: collapse; font-size: 0.875rem; inline-size: 100%; }
    .lw-table th, .lw-table td { padding-block: 0.25rem; padding-inline: 0.5rem; text-align: start;
      border-block-end: 1px solid var(--color-border); vertical-align: top; }
    .lw-input { inline-size: 100%; }
    .lw-key { display: block; font-size: 0.75rem; }
    .lw-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .lw-error { color: var(--color-danger); }
    .lw-badge { font-size: 0.75rem; padding-inline: 0.375rem; border-radius: 999px; border: 1px solid var(--color-border); }
    .lw-badge[data-status="stale"], .lw-badge[data-status="untranslated"] { color: var(--color-danger); }
    .lw-sr { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
  `],
})
export class LabelWorkbenchComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly statuses = WORKBENCH_STATUSES;
  readonly locale = signal('ar-SA');
  readonly status = signal('');
  readonly rows = signal<WorkbenchRow[]>([]);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  private readonly edits = signal<Record<string, string>>({});
  readonly dirtyCount = computed(() => Object.keys(this.edits()).length);

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    const params: Record<string, string> = { locale: this.locale().trim() };
    if (this.status()) params['status'] = this.status();
    this.api.get<{ items: WorkbenchRow[] }>('/api/v1/admin/entities/labels/workbench', params).subscribe({
      next: page => { this.error.set(null); this.rows.set(page.items); this.edits.set({}); },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  draft(row: WorkbenchRow): string {
    return this.edits()[row.key] ?? row.target ?? '';
  }

  edit(row: WorkbenchRow, value: string): void {
    this.edits.update(e => ({ ...e, [row.key]: value }));
  }

  isDirty(row: WorkbenchRow): boolean {
    const edited = this.edits()[row.key];
    return edited !== undefined && edited.trim() !== '' && edited !== (row.target ?? '');
  }

  save(row: WorkbenchRow): void {
    const target = (this.edits()[row.key] ?? '').trim();
    if (!target) return;
    this.busy.set(true);
    this.api.post<{ imported: number; errors: string[] }>(
      '/api/v1/admin/entities/labels/xliff', oneUnitXliff(this.locale().trim(), row, target),
    ).subscribe({
      next: result => {
        this.busy.set(false);
        if (result.errors.length) { this.error.set(result.errors.join('; ')); return; }
        this.load();
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
