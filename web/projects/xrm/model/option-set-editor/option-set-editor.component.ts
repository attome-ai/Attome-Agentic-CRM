import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, TranslatePipe } from '@attome/base';

import { newId } from '../agent-designer/agent-designer.component';
import { ModelService, ObjectSummary } from '../model.service';

/** One value of an option set (`attome_model::kinds::option_set`). */
export interface OptionValue {
  code: string;
  label_en: string;
  label_ar?: string;
  colour?: string;
  order?: number;
  retired?: boolean;
}

/** The light and dark page colours a value's colour is shown on. */
const LIGHT_BG = '#ffffff';
const DARK_BG = '#111827';
/** WCAG AA for normal text. */
export const MIN_CONTRAST = 4.5;

function luminance(hex: string): number {
  const channel = (i: number) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

/** The WCAG contrast ratio between two `#rrggbb` colours. */
export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** Which themes a colour is hard to read on: `light`, `dark`, both or none. */
export function contrastFailures(colour: string | undefined): ('light' | 'dark')[] {
  if (!colour || !/^#[0-9a-fA-F]{6}$/.test(colour)) return [];
  const out: ('light' | 'dark')[] = [];
  if (contrast(colour, LIGHT_BG) < MIN_CONTRAST) out.push('light');
  if (contrast(colour, DARK_BG) < MIN_CONTRAST) out.push('dark');
  return out;
}

/**
 * A5-T4: the option set editor: a set's values with their codes, English and
 * Arabic labels, colours (warned when hard to read in the light or dark
 * theme), order and retirement; saved as a draft and published.
 */
@Component({
  selector: 'xrm-option-set-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <section class="os">
      <aside class="os-list">
        <h2>{{ 'optionSets.title' | translate }}</h2>
        <button type="button" class="btn btn-secondary" (click)="startNew()">{{ 'optionSets.new' | translate }}</button>
        <ul>
          @for (s of sets(); track s.id) {
            <li><button type="button" class="btn btn-text" [class.os-on]="s.id === id()" (click)="open(s)">{{ s.name }}</button></li>
          }
        </ul>
      </aside>
      @if (id()) {
        <div class="os-main">
          <label class="os-name">
            <span>{{ 'optionSets.name' | translate }}</span>
            <input dir="ltr" [ngModel]="name()" (ngModelChange)="name.set($event)" [disabled]="!isNew()" />
          </label>
          <table class="os-table">
            <thead>
              <tr>
                <th scope="col">{{ 'optionSets.code' | translate }}</th>
                <th scope="col">{{ 'optionSets.labelEn' | translate }}</th>
                <th scope="col">{{ 'optionSets.labelAr' | translate }}</th>
                <th scope="col">{{ 'optionSets.colour' | translate }}</th>
                <th scope="col">{{ 'optionSets.order' | translate }}</th>
                <th scope="col">{{ 'optionSets.retired' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (v of values(); track $index; let i = $index) {
                <tr [attr.data-row]="i">
                  <td><input dir="ltr" [ngModel]="v.code" (ngModelChange)="update(i, 'code', $event)" /></td>
                  <td><input dir="ltr" [ngModel]="v.label_en" (ngModelChange)="update(i, 'label_en', $event)" /></td>
                  <td><input dir="rtl" [ngModel]="v.label_ar ?? ''" (ngModelChange)="update(i, 'label_ar', $event)" /></td>
                  <td>
                    <input type="color" [ngModel]="v.colour ?? '#2563eb'" (ngModelChange)="update(i, 'colour', $event)" />
                    @for (theme of failures(v); track theme) {
                      <span class="os-warn" [attr.data-contrast]="theme">{{ 'optionSets.lowContrast_' + theme | translate }}</span>
                    }
                  </td>
                  <td><input type="number" class="os-order" [ngModel]="v.order ?? i + 1" (ngModelChange)="update(i, 'order', $event)" /></td>
                  <td><input type="checkbox" [ngModel]="v.retired ?? false" (ngModelChange)="update(i, 'retired', $event)" /></td>
                </tr>
              }
            </tbody>
          </table>
          <div class="os-actions">
            <button type="button" class="btn btn-text" (click)="addValue()">{{ 'optionSets.addValue' | translate }}</button>
            <button type="button" class="btn btn-secondary" [disabled]="busy()" (click)="save()">{{ 'optionSets.saveDraft' | translate }}</button>
            <button type="button" class="btn btn-primary" [disabled]="busy() || !hash()" (click)="publish()">{{ 'optionSets.publish' | translate }}</button>
            @if (notice(); as n) { <span role="status">{{ n | translate }}</span> }
          </div>
          @for (issue of issues(); track issue) { <p class="os-error" role="alert">{{ issue }}</p> }
        </div>
      }
    </section>
  `,
  styles: [`
    .os { display: flex; gap: 1.5rem; align-items: flex-start; }
    .os-list { min-inline-size: 12rem; display: flex; flex-direction: column; gap: 0.5rem; }
    .os-list h2 { margin-block: 0; font-size: 1.25rem; }
    .os-list ul { list-style: none; margin: 0; padding: 0; }
    .os-on { font-weight: 600; }
    .os-main { flex: 1; display: flex; flex-direction: column; gap: 0.75rem; }
    .os-name { display: flex; align-items: center; gap: 0.5rem; }
    .os-table { border-collapse: collapse; font-size: 0.875rem; }
    .os-table th, .os-table td { padding-block: 0.25rem; padding-inline: 0.375rem; text-align: start;
      border-block-end: 1px solid var(--color-border); }
    .os-order { inline-size: 4rem; }
    .os-warn { display: block; color: var(--color-danger); font-size: 0.75rem; }
    .os-actions { display: flex; align-items: center; gap: 0.5rem; }
    .os-error { color: var(--color-danger); margin: 0; }
  `],
})
export class OptionSetEditorComponent implements OnInit {
  private readonly model = inject(ModelService);

  readonly sets = signal<ObjectSummary[]>([]);
  readonly id = signal<string | null>(null);
  readonly isNew = signal(false);
  readonly name = signal('');
  readonly values = signal<OptionValue[]>([]);
  readonly hash = signal('');
  readonly busy = signal(false);
  readonly notice = signal<string | null>(null);
  readonly issues = signal<string[]>([]);
  readonly valueCount = computed(() => this.values().length);

  ngOnInit(): void {
    this.loadList();
  }

  failures(v: OptionValue): ('light' | 'dark')[] {
    return contrastFailures(v.colour);
  }

  private loadList(): void {
    this.model.objects('option_set', 1).subscribe({
      next: page => this.sets.set(page.items),
      error: () => this.sets.set([]),
    });
  }

  startNew(): void {
    this.id.set(newId());
    this.isNew.set(true);
    this.name.set('');
    this.values.set([{ code: '', label_en: '', order: 1 }]);
    this.hash.set('');
    this.issues.set([]);
    this.notice.set(null);
  }

  open(set: ObjectSummary): void {
    this.model.object('option_set', set.id).subscribe({
      next: object => {
        const doc = object.doc as { values?: OptionValue[] } | null;
        this.id.set(object.id);
        this.isNew.set(false);
        this.name.set(object.name);
        this.values.set(doc?.values ?? []);
        this.hash.set(object.content_hash);
        this.issues.set([]);
        this.notice.set(null);
      },
      error: (e: ApiError) => this.issues.set([e.message]),
    });
  }

  addValue(): void {
    this.values.update(v => [...v, { code: '', label_en: '', order: v.length + 1 }]);
  }

  update(index: number, field: keyof OptionValue, value: unknown): void {
    this.values.update(list => list.map((v, i) => (i === index ? { ...v, [field]: value } : v)));
  }

  /** The values as the kind takes them: empty optional fields left out. */
  cleaned(): OptionValue[] {
    return this.values().map(v => {
      const out: OptionValue = { code: v.code.trim(), label_en: v.label_en.trim() };
      if (v.label_ar?.trim()) out.label_ar = v.label_ar.trim();
      if (v.colour) out.colour = v.colour;
      if (v.order !== undefined && v.order !== null) out.order = Number(v.order);
      if (v.retired) out.retired = true;
      return out;
    });
  }

  save(): void {
    const id = this.id();
    if (!id) return;
    this.busy.set(true);
    this.model.saveDraft('option_set', id, this.isNew() ? '' : this.hash(), this.isNew() ? this.name().trim() : null,
      [{ op: 'set', path: '/values', value: this.cleaned() }]).subscribe({
      next: saved => {
        this.busy.set(false);
        this.isNew.set(false);
        this.hash.set(saved.content_hash);
        this.issues.set(saved.issues.map(i => `${i.path}: ${i.message}`));
        this.notice.set('optionSets.saved');
        this.loadList();
      },
      error: (e: ApiError) => { this.busy.set(false); this.issues.set([e.message]); },
    });
  }

  publish(): void {
    const id = this.id();
    if (!id) return;
    this.busy.set(true);
    this.model.publish('option_set', id).subscribe({
      next: () => { this.busy.set(false); this.notice.set('optionSets.published'); },
      error: (e: ApiError) => { this.busy.set(false); this.issues.set([e.message]); },
    });
  }
}
