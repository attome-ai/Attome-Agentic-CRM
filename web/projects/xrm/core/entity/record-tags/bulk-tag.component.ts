import { ChangeDetectionStrategy, Component, inject, input, output, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

import { TagSuggestionItem } from './record-tags.component';

/** `tags::BulkTagResult`. */
export interface BulkTagResult {
  changed: number;
  failed: { id: string; code: string }[];
}

/**
 * B4-T4: tag or untag the selected records. Type a name and Add (an existing
 * tag is reused, a new one created), or pick a suggestion and Remove. The
 * server checks each record as a single change would and reports the ones it
 * could not change.
 */
@Component({
  selector: 'xrm-bulk-tag',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <span class="bt" data-testid="bulk-tag">
      <button type="button" class="btn btn-secondary" [disabled]="disabled() || busy()" (click)="open.set(!open())">
        <i class="las la-tags" aria-hidden="true"></i> {{ 'recordTags.bulkTag' | translate }}
      </button>
      @if (open()) {
        <span class="bt-panel">
          <input #name type="text" maxlength="80" [placeholder]="'recordTags.add' | translate"
                 [attr.aria-label]="'recordTags.add' | translate" (input)="suggest(name.value)" />
          <button type="button" class="btn btn-primary" [disabled]="busy()" (click)="add(name.value)">
            {{ 'recordTags.bulkAdd' | translate }}
          </button>
          @for (s of suggestions(); track s.id) {
            <button type="button" class="btn btn-text" [disabled]="busy()" (click)="remove(s)"
                    [attr.data-remove]="s.id">
              {{ 'recordTags.bulkRemove' | translate: { tag: s.name } }}
            </button>
          }
          @if (result(); as r) {
            <span role="status">{{ 'recordTags.bulkResult' | translate: { changed: r.changed, failed: r.failed.length } }}</span>
          }
          @if (error()) { <span class="bt-error" role="alert">{{ error() }}</span> }
        </span>
      }
    </span>
  `,
  styles: [`
    .bt { display: inline-flex; align-items: center; gap: 0.5rem; position: relative; }
    .bt-panel { display: inline-flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
    .bt-error { color: var(--color-danger); }
  `],
})
export class BulkTagComponent {
  private readonly api = inject(ApiService);

  readonly entity = input.required<string>();
  readonly recordIds = input.required<readonly string[]>();
  readonly disabled = input(false);
  readonly changed = output<BulkTagResult>();

  readonly open = signal(false);
  readonly busy = signal(false);
  readonly suggestions = signal<TagSuggestionItem[]>([]);
  readonly result = signal<BulkTagResult | null>(null);
  readonly error = signal<string | null>(null);

  suggest(typed: string): void {
    const q = typed.trim();
    if (!q) { this.suggestions.set([]); return; }
    this.api.get<{ items: TagSuggestionItem[] }>('/api/v1/tags/suggest', { q }).subscribe({
      next: page => this.suggestions.set(page.items.slice(0, 5)),
      error: () => this.suggestions.set([]),
    });
  }

  add(typed: string): void {
    const name = typed.trim();
    if (!name) return;
    this.send({ add: { name } });
  }

  remove(tag: TagSuggestionItem): void {
    this.send({ remove_tag_id: tag.id });
  }

  private send(change: { add: { name: string } } | { remove_tag_id: string }): void {
    this.busy.set(true);
    this.error.set(null);
    const path = `/api/v1/${encodeURIComponent(this.entity())}/tags/bulk`;
    this.api.post<BulkTagResult>(path, { ids: [...this.recordIds()], ...change }).subscribe({
      next: result => { this.busy.set(false); this.result.set(result); this.changed.emit(result); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
