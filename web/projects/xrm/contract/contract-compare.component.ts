import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { catchError, of } from 'rxjs';

/** One step of a section's word diff (`compare.rs`'s `Change`). */
export interface WordChange { op: 'equal' | 'insert' | 'delete'; text: string; }

/** A library clause the newer section departs from (`deviations_json`). */
export interface Deviation { section: string; clause_id?: string; clause_key?: string | null; similarity?: number; }

/** One section as the viewer shows it. */
export interface ComparedSection {
  title: string;
  status: 'changed' | 'added' | 'removed';
  /** The older version's words (equal and deleted). */
  before: WordChange[];
  /** The newer version's words (equal and inserted). */
  after: WordChange[];
  deviation: Deviation | null;
}

const asArray = (raw: unknown): unknown[] => {
  if (Array.isArray(raw)) return raw;
  if (typeof raw !== 'string' || !raw.trim()) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

/**
 * A comparison's `diff_json` and `deviations_json` as side-by-side
 * sections: a changed section splits its word diff into the older side
 * (equal and deleted words) and the newer side (equal and inserted words);
 * an added section has only a newer side and a removed one only an older
 * side. Deviations attach to the section of the same title. Pure.
 */
export function parseComparison(diffJson: unknown, deviationsJson: unknown): ComparedSection[] {
  const deviations = new Map<string, Deviation>();
  for (const d of asArray(deviationsJson) as Deviation[]) {
    if (d && typeof d.section === 'string') deviations.set(d.section, d);
  }
  const out: ComparedSection[] = [];
  for (const raw of asArray(diffJson) as Record<string, unknown>[]) {
    if (!raw || typeof raw['section'] !== 'string') continue;
    const title = raw['section'] as string;
    const status = raw['status'] as ComparedSection['status'];
    const deviation = deviations.get(title) ?? null;
    if (status === 'changed') {
      const changes = (Array.isArray(raw['changes']) ? raw['changes'] : []) as WordChange[];
      out.push({
        title, status, deviation,
        before: changes.filter(c => c.op !== 'insert'),
        after: changes.filter(c => c.op !== 'delete'),
      });
    } else if (status === 'added' || status === 'removed') {
      const words: WordChange[] = [{ op: status === 'added' ? 'insert' : 'delete', text: String(raw['text'] ?? '') }];
      out.push({
        title, status, deviation,
        before: status === 'removed' ? words : [],
        after: status === 'added' ? words : [],
      });
    }
  }
  return out;
}

/**
 * W1-T7 / W1-T15: a `contract_comparison` shown side by side, section by
 * section: the older version's words with the removed ones struck, the
 * newer version's with the added ones marked, and a badge where the newer
 * section departs from the clause library. Each side is its own bidi
 * island (`dir="auto"`), so Arabic and English clauses read correctly
 * whichever language the page is in, and the two columns swap sides in
 * Arabic. A comparison still running says so and can be reloaded.
 */
@Component({
  selector: 'xrm-contract-compare',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="cc" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="cc-title" data-testid="cc">
      <header class="cc-head">
        <h2 id="cc-title">{{ 'contractCompare.title' | translate }}</h2>
        @if (deviationCount() > 0) {
          <span class="cc-badge cc-badge--deviation" data-testid="cc-deviation-count">
            {{ 'contractCompare.deviations' | translate: { count: deviationCount() } }}
          </span>
        }
      </header>
      @if (error(); as e) { <p class="cc-error" role="alert">{{ e }}</p> }
      @if (status() === 'queued' || status() === 'running') {
        <p role="status" data-testid="cc-pending">{{ 'contractCompare.pending' | translate }}
          <button type="button" (click)="reload()">{{ 'contractCompare.reload' | translate }}</button></p>
      } @else if (status() === 'failed') {
        <p role="alert" data-testid="cc-failed">{{ 'contractCompare.failed' | translate }}</p>
      } @else if (sections().length === 0 && status() === 'done') {
        <p data-testid="cc-same">{{ 'contractCompare.same' | translate }}</p>
      }
      @for (s of sections(); track s.title + s.status) {
        <article class="cc-section" data-testid="cc-section" [attr.data-status]="s.status">
          <h3>
            <bdi>{{ s.title }}</bdi>
            <span class="cc-badge">{{ 'contractCompare.status.' + s.status | translate }}</span>
            @if (s.deviation; as d) {
              <span class="cc-badge cc-badge--deviation" data-testid="cc-deviation"
                    [attr.title]="'contractCompare.deviationHint' | translate: { key: d.clause_key || '' }">
                {{ 'contractCompare.deviation' | translate }}
                @if (d.similarity !== undefined) { <span dir="ltr">{{ percent(d.similarity) }}%</span> }
              </span>
            }
          </h3>
          <div class="cc-sides">
            <div class="cc-side" [attr.aria-label]="'contractCompare.before' | translate">
              <p class="cc-side-label">{{ 'contractCompare.before' | translate }}</p>
              <p class="cc-text" dir="auto">
                @for (w of s.before; track $index) {
                  @if (w.op === 'delete') { <del data-testid="cc-removed">{{ w.text }}</del> } @else { <span>{{ w.text }}</span> }
                  {{ ' ' }}
                }
              </p>
            </div>
            <div class="cc-side" [attr.aria-label]="'contractCompare.after' | translate">
              <p class="cc-side-label">{{ 'contractCompare.after' | translate }}</p>
              <p class="cc-text" dir="auto">
                @for (w of s.after; track $index) {
                  @if (w.op === 'insert') { <ins data-testid="cc-added">{{ w.text }}</ins> } @else { <span>{{ w.text }}</span> }
                  {{ ' ' }}
                }
              </p>
            </div>
          </div>
        </article>
      }
    </section>
  `,
  styles: [`
    .cc { display: grid; gap: var(--space-3, .75rem); }
    .cc-head { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; }
    .cc-section { border: 1px solid var(--color-border, #ddd); border-radius: 6px; padding: .75rem; }
    .cc-section h3 { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; margin: 0 0 .5rem; font-size: 1rem; }
    .cc-sides { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .75rem; }
    @media (max-width: 40rem) { .cc-sides { grid-template-columns: minmax(0, 1fr); } }
    .cc-side-label { margin: 0 0 .25rem; font-size: .75rem; color: var(--color-text-secondary, #666); }
    .cc-text { margin: 0; white-space: pre-line; unicode-bidi: plaintext; }
    del { background: var(--color-danger-bg, #fde8e8); color: var(--color-danger, #b42318); }
    ins { background: var(--color-success-bg, #e6f4ea); color: var(--color-success, #1e7a3a); text-decoration: none; }
    .cc-badge { font-size: .75rem; padding-inline: .375rem; border-radius: 999px; background: var(--color-bg-alt, #f0f0f0); }
    .cc-badge--deviation { background: var(--color-warning-bg, #fff4e0); color: var(--color-warning, #8a5a00); }
    .cc-error { color: var(--color-danger, #c53030); }
  `],
})
export class ContractCompareComponent {
  private readonly entities = inject(EntityService);
  protected readonly lang = inject(LangService);

  /** The `contract_comparison` record (route parameter or host input). */
  readonly id = input.required<string>();

  protected readonly status = signal<string | null>(null);
  protected readonly sections = signal<ComparedSection[]>([]);
  protected readonly error = signal<string | null>(null);
  protected readonly deviationCount = computed(() => this.sections().filter(s => s.deviation).length);

  constructor() {
    effect(() => {
      const id = this.id();
      untracked(() => this.load(id));
    });
  }

  protected percent(similarity: number): number {
    return Math.round(similarity * 100);
  }

  protected reload(): void {
    this.load(this.id());
  }

  private load(id: string): void {
    this.error.set(null);
    this.entities.get('contract_comparison', id).pipe(
      catchError((e: unknown) => {
        this.error.set(this.lang.errorText(e as ApiError));
        return of(null);
      }),
    ).subscribe(record => {
      if (!record) return;
      const data = (record as unknown as { data: Record<string, unknown> }).data ?? {};
      this.status.set(typeof data['status'] === 'string' ? data['status'] : null);
      this.sections.set(parseComparison(data['diff_json'], data['deviations_json']));
    });
  }
}
