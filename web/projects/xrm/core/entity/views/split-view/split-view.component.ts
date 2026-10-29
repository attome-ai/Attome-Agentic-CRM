import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal, untracked } from '@angular/core';
import { ApiError, TranslatePipe } from '@attome/base';
import { QueryService } from '@attome/xrm/core/query/data';

/** Records one split view reads. */
export const SPLIT_PAGE_SIZE = 50;

/** One column the split view shows on the record side. */
interface SplitColumn { name: string; label: string; }

/** A record value as text, for the record side. Pure. */
export function displayValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—';
  if (Array.isArray(value)) return value.map(displayValue).join(', ');
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

/** The index the arrow keys move to, kept inside the list. Pure. */
export function nextIndex(current: number, key: string, count: number): number {
  if (count === 0) return -1;
  if (key === 'ArrowDown') return Math.min(current + 1, count - 1);
  if (key === 'ArrowUp') return Math.max(current - 1, 0);
  if (key === 'Home') return 0;
  if (key === 'End') return count - 1;
  return current;
}

/**
 * A13-T3: the split view. The list's records on one side, the selected
 * record's fields on the other; the arrow keys (and Home, End) move through
 * the records, Enter opens the selected one. The records come from the same
 * `POST /api/v1/query/execute` feed the list uses (the view's, or the
 * entity's default), so record and field security are the feed's; related
 * columns (A13-T1) show like any other.
 */
@Component({
  selector: 'xrm-split-view',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (error(); as message) {
      <p class="sv-error" role="alert">{{ message }}</p>
    }
    @if (loading()) {
      <p class="sv-muted" role="status">{{ 'entityViews.split.loading' | translate }}</p>
    } @else if (records().length === 0) {
      <p class="sv-muted" data-testid="split-empty">{{ 'entityViews.split.empty' | translate }}</p>
    } @else {
      <div class="sv">
        <ul class="sv-list" role="listbox" tabindex="0" data-testid="split-list"
            [attr.aria-label]="'entityViews.split.list' | translate"
            [attr.aria-activedescendant]="selectedId() ? 'sv-' + selectedId() : null"
            (keydown)="onKey($event)">
          @for (r of records(); track r.id; let i = $index) {
            <li role="option" [id]="'sv-' + r.id" class="sv-item" dir="auto" tabindex="-1"
                (keyup.enter)="index.set(i)"
                [class.sv-active]="i === index()" [attr.aria-selected]="i === index()"
                (click)="index.set(i)" (dblclick)="openRecord.emit(r.id)">{{ r.title }}</li>
          }
        </ul>
        <section class="sv-record" data-testid="split-record" [attr.aria-label]="'entityViews.split.record' | translate">
          @if (selected(); as record) {
            <header class="sv-head">
              <h3 dir="auto">{{ record.title }}</h3>
              <button type="button" class="btn btn-secondary" data-testid="split-open" (click)="openRecord.emit(record.id)">
                {{ 'entityViews.split.open' | translate }}
              </button>
            </header>
            <dl class="sv-fields">
              @for (c of columns(); track c.name) {
                <dt>{{ c.label }}</dt>
                <dd dir="auto">{{ show(record.data[c.name]) }}</dd>
              }
            </dl>
          }
        </section>
      </div>
    }
  `,
  styles: [`
    :host { display: block; }
    .sv { display: grid; grid-template-columns: minmax(12rem, 1fr) 2fr; gap: 1rem; min-block-size: 24rem; }
    .sv-list { list-style: none; margin: 0; padding: 0; border: 1px solid var(--color-border); border-radius: 6px;
      overflow: auto; max-block-size: 70vh; }
    .sv-list:focus-visible { outline: 2px solid var(--color-primary); outline-offset: 2px; }
    .sv-item { padding-block: .5rem; padding-inline: .75rem; cursor: pointer; border-block-end: 1px solid var(--color-border); }
    .sv-active { background: var(--color-bg-alt); font-weight: 600; }
    .sv-record { border: 1px solid var(--color-border); border-radius: 6px; padding: 1rem; overflow: auto; }
    .sv-head { display: flex; justify-content: space-between; align-items: center; gap: 1rem; margin-block-end: .75rem; }
    .sv-head h3 { margin: 0; font-size: 1rem; }
    .sv-fields { display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1rem; margin: 0; }
    .sv-fields dt { color: var(--color-text-secondary); }
    .sv-fields dd { margin: 0; }
    .sv-muted { color: var(--color-text-secondary); margin: 0; }
    .sv-error { color: var(--color-danger); margin: 0; }
    @media (max-width: 640px) { .sv { grid-template-columns: 1fr; } }
  `],
})
export class SplitViewComponent {
  readonly entityName = input.required<string>();
  /** The list view to read; the entity's default list when absent. */
  readonly viewId = input<string | null>(null);
  readonly openRecord = output<string>();

  private readonly querySvc = inject(QueryService);

  readonly loading = signal(false);
  readonly error = signal<string | null>(null);
  readonly records = signal<{ id: string; title: string; data: Record<string, unknown> }[]>([]);
  readonly columns = signal<SplitColumn[]>([]);
  readonly index = signal(0);
  readonly selected = computed(() => this.records()[this.index()] ?? null);
  readonly selectedId = computed(() => this.selected()?.id ?? null);

  private generation = 0;

  constructor() {
    effect(() => {
      const entity = this.entityName();
      const view = this.viewId();
      untracked(() => this.load(entity, view));
    });
  }

  show(value: unknown): string {
    return displayValue(value);
  }

  onKey(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      const id = this.selectedId();
      if (id) this.openRecord.emit(id);
      event.preventDefault();
      return;
    }
    const next = nextIndex(this.index(), event.key, this.records().length);
    if (next !== this.index() || ['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      this.index.set(Math.max(next, 0));
      const host = event.currentTarget as HTMLElement | null;
      const item = host?.querySelectorAll<HTMLElement>('[role="option"]')[this.index()];
      item?.scrollIntoView?.({ block: 'nearest' });
    }
  }

  private load(entity: string, view: string | null): void {
    const generation = ++this.generation;
    this.loading.set(true);
    this.error.set(null);
    this.querySvc.execute({
      ...(view ? { view_id: view } : { entity }),
      page: 1, page_size: SPLIT_PAGE_SIZE, include_total: false,
    }).subscribe({
      next: res => {
        if (generation !== this.generation) return;
        const visible = res.data.columns.filter(c => c.is_visible && c.name !== 'id');
        const titleField = visible[0]?.name;
        this.columns.set(visible.map(c => ({ name: c.name, label: c.display_name || c.name })));
        this.records.set(res.data.records.map(r => {
          const id = String(r['id'] ?? '');
          const title = titleField ? r[titleField] : null;
          return { id, title: title === null || title === undefined || title === '' ? id : String(title), data: r };
        }));
        this.index.set(0);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        if (generation !== this.generation) return;
        this.loading.set(false);
        this.error.set(e.message);
      },
    });
  }
}
