import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject, input, output, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { TranslatePipe } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { Subject, catchError, debounceTime, distinctUntilChanged, forkJoin, map, of, switchMap } from 'rxjs';

import { EntityService } from '../../services/entity.service';

/** One picked target of a polymorphic lookup (A8-T1's pair). */
export interface PolymorphicValue {
  entity: string;
  id: string;
  label: string;
}

/** The hits of one allowed entity. */
export interface PolymorphicGroup {
  entity: string;
  icon: string;
  hits: { id: string; label: string }[];
}

/** Results per entity the picker shows. */
export const PER_ENTITY = 5;

/** An entity's icon: a record's usual shape, else a generic one. Pure. */
export function entityIcon(entity: string, icons: Readonly<Record<string, string>>): string {
  return icons[entity] ?? 'las la-file-alt';
}

/** A record's display text: its display field, else `name`, else its id. Pure. */
export function recordLabel(record: EntityRecord, field: string): string {
  const data = record.data as Record<string, unknown>;
  const value = data[field] ?? data['name'] ?? data['title'];
  return typeof value === 'string' && value.trim() ? value : record.id;
}

/**
 * A8-T5: the picker of a polymorphic ("regarding") lookup. One search box
 * searches every allowed entity at once and lists the hits grouped by
 * entity, each with the entity's icon and the record's name; picking one
 * emits the pair (entity, record id) the field stores in its two
 * attributes. Text matching is the server's `contains` filter on each
 * entity's display field, so Arabic text matches as the database compares
 * it (A8-T1's write check still decides what may be stored).
 */
@Component({
  selector: 'xrm-polymorphic-lookup',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  templateUrl: './polymorphic-lookup.component.html',
  styleUrl: './polymorphic-lookup.component.css',
})
export class PolymorphicLookupComponent {
  private readonly entities = inject(EntityService);

  /** The entities the field may point at. */
  readonly targets = input.required<string[]>();
  /** Per entity, the attribute that names a record (default `name`). */
  readonly displayFields = input<Readonly<Record<string, string>>>({});
  /** Per entity, its icon class. */
  readonly icons = input<Readonly<Record<string, string>>>({});
  /** The current value, when there is one. */
  readonly value = input<PolymorphicValue | null>(null);
  readonly disabled = input(false);

  readonly picked = output<PolymorphicValue | null>();

  readonly term = signal('');
  readonly groups = signal<PolymorphicGroup[]>([]);
  readonly searching = signal(false);
  readonly open = signal(false);
  readonly hitCount = computed(() => this.groups().reduce((n, g) => n + g.hits.length, 0));

  private readonly terms = new Subject<string>();

  constructor() {
    this.terms.pipe(
      debounceTime(250),
      distinctUntilChanged(),
      switchMap(term => this.search(term)),
      takeUntilDestroyed(inject(DestroyRef)),
    ).subscribe(groups => {
      this.groups.set(groups);
      this.searching.set(false);
    });
  }

  /** Every allowed entity searched at once; an entity that fails shows nothing. */
  search(term: string) {
    const text = term.trim();
    if (text.length < 2) return of<PolymorphicGroup[]>([]);
    const fields = this.displayFields();
    const icons = this.icons();
    return forkJoin(this.targets().map(entity => {
      const field = fields[entity] ?? 'name';
      return this.entities.lookupSearch(entity, text, field).pipe(
        map(page => ({
          entity,
          icon: entityIcon(entity, icons),
          hits: page.data.slice(0, PER_ENTITY).map(r => ({ id: r.id, label: recordLabel(r, field) })),
        })),
        catchError(() => of({ entity, icon: entityIcon(entity, icons), hits: [] })),
      );
    })).pipe(map(groups => groups.filter(g => g.hits.length > 0)));
  }

  iconOf(entity: string): string {
    return entityIcon(entity, this.icons());
  }

  onInput(event: Event): void {
    const text = (event.target as HTMLInputElement).value;
    this.term.set(text);
    this.open.set(true);
    this.searching.set(text.trim().length >= 2);
    this.terms.next(text);
  }

  pick(entity: string, hit: { id: string; label: string }): void {
    this.picked.emit({ entity, id: hit.id, label: hit.label });
    this.open.set(false);
    this.term.set('');
    this.groups.set([]);
  }

  clear(): void {
    this.picked.emit(null);
  }
}
