import { ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { Subject, catchError, debounceTime, distinctUntilChanged, map, of, switchMap } from 'rxjs';

import { EntityService } from '@attome/xrm/core/entity/data';
import { recordLabel } from '../polymorphic-lookup/polymorphic-lookup.component';

/** One linked record, as a chip. */
export interface Chip {
  id: string;
  label: string;
}

/** Hits the search offers. */
export const HITS = 8;

/** Whether the chips differ from what is saved, as sets. Pure. */
export function chipsChanged(saved: readonly Chip[], current: readonly Chip[]): boolean {
  if (saved.length !== current.length) return true;
  const ids = new Set(saved.map(c => c.id));
  return current.some(c => !ids.has(c.id));
}

/**
 * A2-T5: the multi-lookup control, chips over a many-to-many relationship
 * (A2-T4). It shows the record's linked records on `relationship` as
 * chips, searches the other side by its display field to add one, removes
 * a chip with its button, and saves the set in one call
 * (`PUT .../related/{relationship}`), which links and unlinks in one
 * transaction. Logical CSS only, so it reads right to left in Arabic.
 */
@Component({
  selector: 'xrm-multi-lookup',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <div class="ml" data-testid="multi-lookup">
      <ul class="ml-chips" [attr.aria-label]="label() || ('multiLookup.linked' | translate)">
        @for (chip of chips(); track chip.id) {
          <li class="ml-chip" [attr.data-id]="chip.id">
            <span dir="auto">{{ chip.label }}</span>
            @if (!disabled()) {
              <button type="button" class="ml-remove" [attr.aria-label]="'multiLookup.remove' | translate: { name: chip.label }"
                      (click)="remove(chip.id)">
                <i class="las la-times" aria-hidden="true"></i>
              </button>
            }
          </li>
        } @empty {
          <li class="ml-empty">{{ 'multiLookup.none' | translate }}</li>
        }
      </ul>
      @if (!disabled()) {
        <input type="search" class="xf-input ml-search" dir="auto" [value]="term()"
               [attr.aria-label]="'multiLookup.search' | translate" [placeholder]="'multiLookup.search' | translate"
               (input)="onInput($event)" data-testid="multi-lookup-search" />
        @if (hits().length) {
          <ul class="ml-hits" role="listbox" [attr.aria-label]="'multiLookup.results' | translate">
            @for (hit of hits(); track hit.id) {
              <li role="option" [attr.aria-selected]="false">
                <button type="button" class="ml-hit" (click)="add(hit)">{{ hit.label }}</button>
              </li>
            }
          </ul>
        }
        <div class="ml-actions">
          <button type="button" data-testid="multi-lookup-save" [disabled]="!dirty() || saving()" (click)="save()">
            {{ (saving() ? 'multiLookup.saving' : 'multiLookup.save') | translate }}
          </button>
          @if (error(); as e) { <span class="ml-error" role="alert">{{ e }}</span> }
        </div>
      }
    </div>
  `,
  styles: [`
    .ml { display: grid; gap: .5rem; }
    .ml-chips { display: flex; flex-wrap: wrap; gap: .375rem; margin: 0; padding: 0; list-style: none; }
    .ml-chip { display: inline-flex; align-items: center; gap: .25rem; border: 1px solid var(--color-border, #ccc);
      border-radius: 999px; padding-block: .125rem; padding-inline: .625rem .25rem; }
    .ml-remove { border: none; background: none; cursor: pointer; color: inherit; padding: 0; }
    .ml-empty { color: var(--color-text-secondary, #666); }
    .ml-hits { margin: 0; padding: 0; list-style: none; border: 1px solid var(--color-border, #ddd); border-radius: 6px; }
    .ml-hit { inline-size: 100%; text-align: start; border: none; background: none; padding-block: .25rem; padding-inline: .5rem; cursor: pointer; }
    .ml-actions { display: flex; align-items: center; gap: .5rem; }
    .ml-error { color: var(--color-danger, #c53030); }
  `],
})
export class MultiLookupComponent {
  private readonly entities = inject(EntityService);
  private readonly lang = inject(LangService);

  /** The record's entity and id. */
  readonly entity = input.required<string>();
  readonly recordId = input.required<string>();
  /** The many-to-many relationship. */
  readonly relationship = input.required<string>();
  /** The other side's entity, and the attribute that names its records. */
  readonly otherEntity = input.required<string>();
  readonly displayField = input('name');
  readonly label = input('');
  readonly disabled = input(false);

  readonly saved = signal<readonly Chip[]>([]);
  readonly chips = signal<readonly Chip[]>([]);
  readonly hits = signal<readonly Chip[]>([]);
  readonly term = signal('');
  readonly saving = signal(false);
  readonly error = signal<string | null>(null);
  readonly dirty = computed(() => chipsChanged(this.saved(), this.chips()));

  private readonly terms = new Subject<string>();

  constructor() {
    effect(() => {
      const [entity, id, relationship] = [this.entity(), this.recordId(), this.relationship()];
      untracked(() => this.load(entity, id, relationship));
    });
    this.terms.pipe(
      debounceTime(250),
      distinctUntilChanged(),
      switchMap(term => this.search(term)),
      takeUntilDestroyed(inject(DestroyRef)),
    ).subscribe(hits => this.hits.set(hits));
  }

  /** The other side's records matching `term`, those already chips left out. */
  search(term: string) {
    const text = term.trim();
    if (text.length < 2) return of<Chip[]>([]);
    const field = this.displayField();
    return this.entities.lookupSearch(this.otherEntity(), text, field).pipe(
      map(page => {
        const taken = new Set(this.chips().map(c => c.id));
        return page.data
          .filter(r => !taken.has(r.id))
          .slice(0, HITS)
          .map(r => ({ id: r.id, label: recordLabel(r, field) }));
      }),
      catchError(() => of<Chip[]>([])),
    );
  }

  onInput(event: Event): void {
    const text = (event.target as HTMLInputElement).value;
    this.term.set(text);
    this.terms.next(text);
  }

  add(chip: Chip): void {
    if (!this.chips().some(c => c.id === chip.id)) this.chips.update(list => [...list, chip]);
    this.hits.set([]);
    this.term.set('');
  }

  remove(id: string): void {
    this.chips.update(list => list.filter(c => c.id !== id));
  }

  save(): void {
    this.saving.set(true);
    this.error.set(null);
    const ids = this.chips().map(c => c.id);
    this.entities.replaceRelated(this.entity(), this.recordId(), this.relationship(), ids).subscribe({
      next: () => {
        this.saving.set(false);
        this.saved.set(this.chips());
      },
      error: (e: ApiError) => {
        this.saving.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  private load(entity: string, id: string, relationship: string): void {
    const field = this.displayField();
    this.entities.listRelated(entity, id, relationship, 1, 200).subscribe({
      next: page => {
        const chips = page.items.map(r => {
          const data = (r.data ?? {}) as Record<string, unknown>;
          const value = data[field] ?? data['name'] ?? data['title'];
          return { id: String(r.id), label: typeof value === 'string' && value.trim() ? value : String(r.id) };
        });
        this.saved.set(chips);
        this.chips.set(chips);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }
}
