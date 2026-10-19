import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { ApiService, TranslatePipe } from '@attome/base';

/** A cited passage (`GET /api/v1/search/knowledge`, `KnowledgeCitation`). */
export interface ArticleSuggestion {
  item_id: string;
  title: string;
  passage: string;
}

type Feedback = 'useful' | 'not_useful' | 'unavailable';

/** Longest case text sent as the query. */
const MAX_QUERY = 500;

/** The query for a case: its title and description, trimmed. Pure. */
export function caseQuery(title: string | null | undefined, description: string | null | undefined): string {
  return [title, description]
    .map(s => (s ?? '').trim())
    .filter(Boolean)
    .join(' ')
    .slice(0, MAX_QUERY);
}

/**
 * G11-T2: knowledge articles suggested for the case in front of an agent,
 * found by the case's own text (N15 knowledge search, under the agent's
 * permissions), each with "helpful" and "not helpful" which count on the
 * article (G11-T1). A suggestion that is not a published article takes no
 * feedback and says so.
 */
@Component({
  selector: 'xrm-article-suggest',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="as" [attr.aria-label]="'articleSuggest.title' | translate">
      <h4 class="as-title">{{ 'articleSuggest.title' | translate }}</h4>
      @for (s of suggestions(); track s.item_id) {
        <article class="as-item" data-testid="article-suggestion">
          <strong>{{ s.title }}</strong>
          <p class="as-passage">{{ s.passage }}</p>
          @switch (feedback()[s.item_id]) {
            @case ('useful') { <span class="as-note" role="status">{{ 'articleSuggest.thanks' | translate }}</span> }
            @case ('not_useful') { <span class="as-note" role="status">{{ 'articleSuggest.thanks' | translate }}</span> }
            @case ('unavailable') { <span class="as-note" data-testid="article-no-feedback">{{ 'articleSuggest.noFeedback' | translate }}</span> }
            @default {
              <div class="as-actions">
                <button type="button" class="as-btn" (click)="vote(s, true)" data-testid="article-useful">
                  <i class="las la-thumbs-up" aria-hidden="true"></i> {{ 'articleSuggest.helpful' | translate }}
                </button>
                <button type="button" class="as-btn" (click)="vote(s, false)" data-testid="article-not-useful">
                  <i class="las la-thumbs-down" aria-hidden="true"></i> {{ 'articleSuggest.notHelpful' | translate }}
                </button>
              </div>
            }
          }
        </article>
      } @empty {
        <p class="as-note" data-testid="article-none">{{ 'articleSuggest.none' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .as { display: grid; gap: 8px; }
    .as-title { margin: 0; font-size: 14px; }
    .as-item { border: 1px solid var(--color-border); border-radius: 8px; padding-block: 8px; padding-inline: 10px; display: grid; gap: 4px; }
    .as-passage { margin: 0; font-size: 13px; color: var(--color-text-secondary); }
    .as-actions { display: flex; gap: 6px; }
    .as-btn { display: inline-flex; align-items: center; gap: 4px; padding-block: 4px; padding-inline: 8px;
              border: 1px solid var(--color-border); border-radius: 6px; background: var(--color-bg); color: var(--color-text-primary); cursor: pointer; }
    .as-note { font-size: 12px; color: var(--color-text-secondary); }
  `],
})
export class ArticleSuggestComponent {
  private readonly api = inject(ApiService);

  /** The case text to suggest articles for. */
  readonly text = input<string>('');

  readonly suggestions = signal<ArticleSuggestion[]>([]);
  readonly feedback = signal<Record<string, Feedback>>({});

  constructor() {
    effect(() => {
      const q = this.text().trim();
      this.feedback.set({});
      if (q.length < 3) {
        this.suggestions.set([]);
        return;
      }
      this.api.get<{ items: ArticleSuggestion[] }>('/api/v1/search/knowledge', { q, limit: '3' }).subscribe({
        next: page => this.suggestions.set(page.items),
        error: () => this.suggestions.set([]),
      });
    });
  }

  vote(s: ArticleSuggestion, useful: boolean): void {
    this.api.post<unknown>('/api/v1/content/knowledge-feedback', { item_id: s.item_id, useful }).subscribe({
      next: () => this.mark(s.item_id, useful ? 'useful' : 'not_useful'),
      // Only "not an article" is final; anything else leaves the buttons.
      error: (e: { kind?: string }) => {
        if (e?.kind === 'not_found') this.mark(s.item_id, 'unavailable');
      },
    });
  }

  private mark(itemId: string, value: Feedback): void {
    this.feedback.update(f => ({ ...f, [itemId]: value }));
  }
}
