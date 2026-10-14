import { ChangeDetectionStrategy, Component, Injector, effect, inject, input, signal } from '@angular/core';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import { Subject, debounceTime, distinctUntilChanged, of, switchMap } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';

/** A tag on a record (`TagView`). */
export interface RecordTag {
  id: string;
  name: string;
  colour: string | null;
  group_id: string | null;
  personal: boolean;
}

/** A suggestion while typing (`TagSuggestion`). */
export interface TagSuggestionItem {
  id: string;
  name: string;
  colour: string | null;
  personal: boolean;
  uses: number;
}

interface Page<T> { items: T[] }

/**
 * B4-T4: the tags under a record's title — chips, with an input that suggests
 * existing tags (ignoring case and Arabic diacritics) and creates a new one
 * on Enter. A personal tag (only you see it) is marked; removing a shared
 * tag needs update access to the record, which the server checks.
 */
@Component({
  selector: 'xrm-record-tags',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./record-tags.component.css'],
  templateUrl: './record-tags.component.html',
})
export class RecordTagsComponent {
  readonly entity = input.required<string>();
  readonly recordId = input.required<string>();

  private readonly injector = inject(Injector);
  private readonly lang = inject(LangService);

  readonly tags = signal<RecordTag[]>([]);
  readonly suggestions = signal<TagSuggestionItem[]>([]);
  readonly typed = signal('');
  readonly personal = signal(false);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);

  private readonly typing = new Subject<string>();

  /**
   * The API client, resolved on first use: tags are an addition to a form,
   * so a host without an HTTP client (a preview, a form test) renders none
   * instead of failing the form.
   */
  private get api(): ApiService | null {
    try {
      return this.injector.get(ApiService);
    } catch {
      return null;
    }
  }

  constructor() {
    effect(() => {
      const entity = this.entity();
      const id = this.recordId();
      this.api?.get<Page<RecordTag>>(this.path(entity, id)).subscribe({
        next: page => this.tags.set(page.items),
        error: () => this.tags.set([]),
      });
    });
    this.typing.pipe(
      debounceTime(200),
      distinctUntilChanged(),
      switchMap(q => {
        const api = this.api;
        return q.trim() && api
          ? api.get<Page<TagSuggestionItem>>('/api/v1/tags/suggest', { q: q.trim() })
          : of({ items: [] as TagSuggestionItem[] });
      }),
      takeUntilDestroyed(),
    ).subscribe({
      next: page => this.suggestions.set(page.items.filter(s => !this.tags().some(t => t.id === s.id))),
      error: () => this.suggestions.set([]),
    });
  }

  /** B4-T4: the tag page, through the router when there is one. */
  openTag(event: Event, tag: RecordTag): void {
    const router = this.injector.get(Router, null);
    if (!router) return;
    event.preventDefault();
    void router.navigate(['/xrm/tags', tag.id]);
  }

  private path(entity: string, id: string): string {
    return `/api/v1/${encodeURIComponent(entity)}/${encodeURIComponent(id)}/tags`;
  }

  onInput(value: string): void {
    this.typed.set(value);
    this.typing.next(value);
  }

  /** Adds an existing tag, or creates one from what was typed. */
  add(suggestion?: TagSuggestionItem): void {
    const name = this.typed().trim();
    if (this.busy() || (!suggestion && !name)) return;
    const body = suggestion
      ? { tag_id: suggestion.id }
      : { name, personal: this.personal() };
    const api = this.api;
    if (!api) return;
    this.busy.set(true);
    this.error.set(null);
    api.post<Page<RecordTag>>(this.path(this.entity(), this.recordId()), body).subscribe({
      next: page => {
        this.tags.set(page.items);
        this.typed.set('');
        this.suggestions.set([]);
        this.busy.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.busy.set(false);
      },
    });
  }

  remove(tag: RecordTag): void {
    const api = this.api;
    if (this.busy() || !api) return;
    this.busy.set(true);
    this.error.set(null);
    api.delete(`${this.path(this.entity(), this.recordId())}/${encodeURIComponent(tag.id)}`).subscribe({
      next: () => {
        this.tags.update(all => all.filter(t => t.id !== tag.id));
        this.busy.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.busy.set(false);
      },
    });
  }

  onKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      event.preventDefault();
      const exact = this.suggestions().find(s => s.name.toLowerCase() === this.typed().trim().toLowerCase());
      this.add(exact);
    } else if (event.key === 'Escape') {
      this.suggestions.set([]);
    }
  }
}
