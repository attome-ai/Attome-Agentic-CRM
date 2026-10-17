import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';
import { EntityService, logicalToUrlPath } from '@attome/xrm/core/entity';

/** `attome_sales::competitor_routes::SalesBattlecard`. */
export interface SalesBattlecard {
  competitor_id: string;
  name: string | null;
  status: string | null;
  threat_level: string | null;
  battlecard_ref: string | null;
}

/** `attome_sales::competitor_drafts::CompetitorCard`. */
export interface CompetitorCard {
  competitor_id: string;
  competitor: Record<string, unknown>;
  article: Record<string, unknown> | null;
}

/** A `competitor_mention` still waiting for a person. */
export interface ProposedMention {
  id: string;
  competitor_ref: string;
  snippet: string;
  row_version: number;
}

function text(record: Record<string, unknown> | null | undefined, field: string): string {
  const value = record?.[field];
  return typeof value === 'string' ? value.trim() : '';
}

/**
 * The battle card panel on a deal (roadmap D25-T9). It stays hidden until
 * the deal has a competitor, a proposed mention or a review to finish, so a
 * deployment without the competitor part of the sales pack (the battle card
 * route answers 404) never sees it.
 *
 * - One tab per competitor on the deal; the open tab shows the competitor's
 *   strengths, weaknesses and price position and its knowledge article.
 * - Proposed mentions found in emails and notes, each with confirm (puts the
 *   competitor on the deal) and reject.
 * - When a closed deal's win-loss review is still empty, a banner that opens
 *   the review in its generic form.
 *
 * Text comes from the catalogue and layout uses logical properties only, so
 * the panel mirrors in Arabic.
 */
@Component({
  selector: 'xrm-battlecard-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  template: `
    @if (visible()) {
      <section class="bcp" aria-labelledby="bcp-title">
        <h3 id="bcp-title">{{ 'battlecards.title' | translate }}</h3>
        @if (error(); as message) { <p class="bcp-error" role="alert">{{ message }}</p> }

        @if (reviewLink(); as link) {
          <p class="bcp-review" role="status">
            <span>{{ 'battlecards.reviewPending' | translate }}</span>
            <a [routerLink]="link.path" [queryParams]="link.query">{{ 'battlecards.openReview' | translate }}</a>
          </p>
        }

        @if (mentions().length) {
          <div class="bcp-mentions">
            <h4>{{ 'battlecards.proposed' | translate }}</h4>
            <ul>
              @for (m of mentions(); track m.id) {
                <li class="bcp-chip" [attr.data-mention]="m.id">
                  <strong>{{ competitorName(m.competitor_ref) }}</strong>
                  <q>{{ m.snippet }}</q>
                  <button type="button" (click)="decide(m, true)" [disabled]="busy()">{{ 'battlecards.confirm' | translate }}</button>
                  <button type="button" (click)="decide(m, false)" [disabled]="busy()">{{ 'battlecards.reject' | translate }}</button>
                </li>
              }
            </ul>
          </div>
        }

        @if (cards().length) {
          <div class="bcp-tabs" role="tablist">
            @for (c of cards(); track c.competitor_id) {
              <button type="button" role="tab" [attr.aria-selected]="c.competitor_id === active()"
                      [attr.data-competitor]="c.competitor_id" (click)="open(c.competitor_id)">
                {{ c.name || c.competitor_id }}
                @if (c.threat_level) { <small>{{ 'battlecards.threat.' + c.threat_level | translate }}</small> }
              </button>
            }
          </div>
          @if (card(); as k) {
            <div class="bcp-card" role="tabpanel">
              <dl>
                @if (field(k.competitor, 'strengths'); as v) { <dt>{{ 'battlecards.strengths' | translate }}</dt><dd>{{ v }}</dd> }
                @if (field(k.competitor, 'weaknesses'); as v) { <dt>{{ 'battlecards.weaknesses' | translate }}</dt><dd>{{ v }}</dd> }
                @if (field(k.competitor, 'price_position'); as v) {
                  <dt>{{ 'battlecards.price' | translate }}</dt><dd>{{ 'battlecards.priceValue.' + v | translate }}</dd>
                }
              </dl>
              @if (k.article; as a) {
                <article class="bcp-article">
                  <h4>{{ field(a, 'title') }}</h4>
                  <p>{{ field(a, 'body') }}</p>
                </article>
              } @else {
                <p class="bcp-muted">{{ 'battlecards.noArticle' | translate }}</p>
              }
            </div>
          }
        }
      </section>
    }
  `,
  styles: [`
    :host { display: block; }
    .bcp { display: flex; flex-direction: column; gap: 0.75rem; padding-block: 0.75rem;
      border-block-start: 1px solid var(--color-border); }
    .bcp h3 { margin-block: 0; font-size: 1rem; }
    .bcp h4 { margin-block: 0 0.375rem; font-size: 0.875rem; }
    .bcp ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.375rem; }
    .bcp-chip { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; padding-block: 0.25rem;
      padding-inline: 0.5rem; border: 1px solid var(--color-border); border-radius: 0.5rem; }
    .bcp-chip q { flex: 1 1 12rem; color: var(--color-text-secondary); }
    .bcp-tabs { display: flex; flex-wrap: wrap; gap: 0.25rem; }
    .bcp-tabs [aria-selected="true"] { border-block-end: 2px solid var(--color-primary); }
    .bcp-tabs small { margin-inline-start: 0.375rem; color: var(--color-text-secondary); }
    .bcp-card dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 0.75rem; margin: 0; }
    .bcp-card dt { font-weight: 600; }
    .bcp-card dd { margin: 0; white-space: pre-wrap; }
    .bcp-article p { white-space: pre-wrap; margin: 0; }
    .bcp-review { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; margin: 0;
      padding-block: 0.5rem; padding-inline: 0.75rem; background: var(--color-bg-alt); border-radius: 0.5rem; }
    .bcp-muted { color: var(--color-text-secondary); font-size: 0.8125rem; margin: 0; }
    .bcp-error { color: var(--color-danger); margin: 0; }
  `],
})
export class BattlecardPanelComponent {
  private readonly api = inject(ApiService);
  private readonly entities = inject(EntityService);

  readonly opportunityId = input<string | null>(null);

  readonly cards = signal<SalesBattlecard[]>([]);
  readonly mentions = signal<ProposedMention[]>([]);
  readonly pendingReview = signal<string | null>(null);
  readonly active = signal<string | null>(null);
  readonly card = signal<CompetitorCard | null>(null);
  readonly names = signal<Record<string, string>>({});
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  readonly visible = computed(
    () => this.cards().length > 0 || this.mentions().length > 0 || this.pendingReview() !== null,
  );

  readonly reviewLink = computed(() => {
    const id = this.pendingReview();
    return id ? { path: `/${logicalToUrlPath('win_loss_review')}/form`, query: { id } } : null;
  });

  readonly field = text;

  constructor() {
    // Only the deal id is tracked: loading reads and writes the panel's own
    // signals, which must not re-run this effect.
    effect(() => {
      const id = this.opportunityId();
      untracked(() => {
        this.cards.set([]);
        this.mentions.set([]);
        this.pendingReview.set(null);
        this.card.set(null);
        this.active.set(null);
        if (id) this.load(id);
      });
    });
  }

  competitorName(id: string): string {
    return this.cards().find(c => c.competitor_id === id)?.name ?? this.names()[id] ?? id;
  }

  load(id: string): void {
    // A 404 means competitors are not installed: the panel stays hidden.
    this.api.get<{ items: SalesBattlecard[] }>(`/api/v1/sales/opportunities/${encodeURIComponent(id)}/battlecards`).subscribe({
      next: page => {
        const cards = page.items;
        this.cards.set(cards);
        if (cards.length && !this.active()) this.open(cards[0].competitor_id);
        this.loadMentions(id);
        this.loadReview(id);
      },
      error: () => this.cards.set([]),
    });
  }

  open(competitorId: string): void {
    this.active.set(competitorId);
    this.card.set(null);
    this.api.get<CompetitorCard>(`/api/v1/sales/competitors/${encodeURIComponent(competitorId)}/card`).subscribe({
      next: card => { if (this.active() === competitorId) this.card.set(card); },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  decide(mention: ProposedMention, confirm: boolean): void {
    const id = this.opportunityId();
    this.busy.set(true);
    const verb = confirm ? 'confirm' : 'reject';
    this.api.post(`/api/v1/sales/competitor-mentions/${encodeURIComponent(mention.id)}/${verb}`, {},
      { ifMatch: mention.row_version }).subscribe({
      next: () => { this.busy.set(false); if (id) this.load(id); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  private loadMentions(id: string): void {
    this.entities.list('competitor_mention', {
      filters: [
        { field: 'opportunity_ref', op: 'eq', value: id },
        { field: 'status', op: 'eq', value: 'proposed' },
      ],
      sorts: [{ field: 'created_at', dir: 'desc' }],
      limit: 20,
    }).subscribe({
      next: page => {
        const mentions = page.data.map(r => ({
          id: r.id,
          competitor_ref: String(r.data['competitor_ref'] ?? ''),
          snippet: String(r.data['snippet'] ?? ''),
          row_version: r.row_version,
        }));
        this.mentions.set(mentions);
        for (const ref of new Set(mentions.map(m => m.competitor_ref))) {
          if (ref && !this.cards().some(c => c.competitor_id === ref)) this.loadName(ref);
        }
      },
      error: () => this.mentions.set([]),
    });
  }

  private loadName(ref: string): void {
    this.entities.get('competitor', ref).subscribe({
      next: r => {
        const name = text((r as { data?: Record<string, unknown> }).data, 'name');
        if (name) this.names.update(n => ({ ...n, [ref]: name }));
      },
      error: () => undefined,
    });
  }

  /** The deal's review, when it exists and has no main reason yet. */
  private loadReview(id: string): void {
    this.entities.list('win_loss_review', {
      filters: [{ field: 'opportunity_ref', op: 'eq', value: id }],
      limit: 5,
    }).subscribe({
      next: page => {
        const open = page.data.find(r => !r.data['main_reason']);
        this.pendingReview.set(open ? open.id : null);
      },
      error: () => this.pendingReview.set(null),
    });
  }
}
