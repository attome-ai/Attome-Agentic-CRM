import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

import { showValue } from './metadata-layers.model';
import type { ConflictChoice, ConflictProposal, LayerConflict } from './metadata-layers.model';

/** The Y11-T8 action that proposes a resolution; it never resolves. */
export const PROPOSE_CONFLICT_ACTION = 'metadata.propose_conflict_resolution';

/**
 * Y11-T15: the upgrade conflicts still open: properties the platform changed
 * that the customer (or an app) had changed too. Each is resolved by a click:
 * keep mine, take the platform's, or combine into an edited value. "Ask the
 * agent" shows the agent's proposal and reasoning and fills the choice in;
 * nothing is resolved until the builder clicks Resolve. Logical CSS only.
 */
@Component({
  selector: 'xrm-metadata-conflicts',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  template: `
    <section class="mc">
      <h3>{{ 'metadataLayers.conflictsTitle' | translate }}</h3>
      <p class="mc-muted">{{ 'metadataLayers.conflictsIntro' | translate }}</p>
      @if (error(); as message) { <p class="mc-error" role="alert">{{ message }}</p> }
      @if (badJson()) { <p class="mc-error" role="alert">{{ 'metadataLayers.badJson' | translate }}</p> }

      @if (conflicts().length === 0) {
        <p class="mc-muted">{{ 'metadataLayers.noConflicts' | translate }}</p>
      }
      @for (c of conflicts(); track c.id) {
        <article class="mc-card" [attr.data-conflict]="c.id">
          <header class="mc-head">
            <strong dir="ltr">{{ c.object_key }} · {{ c.property }}</strong>
            <span class="mc-muted">{{ ('metadataLayers.kinds.' + c.object_kind) | translate }} · {{ c.created_at | localDate }}</span>
          </header>
          <dl class="mc-values">
            <dt>{{ 'metadataLayers.oldPlatform' | translate }}</dt><dd dir="auto">{{ show(c.old_platform) }}</dd>
            <dt>{{ 'metadataLayers.newPlatform' | translate }}</dt><dd dir="auto">{{ show(c.new_platform) }}</dd>
            <dt>{{ 'metadataLayers.mine' | translate }}</dt><dd dir="auto">{{ show(c.customer) }}</dd>
          </dl>

          @if (proposals()[c.id]; as p) {
            <div class="mc-proposal" role="status">
              @if (p.status === 'proposed') {
                <p>
                  <strong>{{ 'metadataLayers.agentSuggests' | translate }}</strong>
                  {{ ('metadataLayers.choices.' + p.choice) | translate }}
                  @if (p.choice === 'combine') { <span dir="auto">({{ show(p.value) }})</span> }
                </p>
                <p dir="auto" class="mc-reasoning">{{ p.reasoning }}</p>
              } @else {
                <p class="mc-muted">{{ 'metadataLayers.agentDeclined' | translate }}</p>
              }
            </div>
          }

          @if (combining() === c.id) {
            <label class="mc-combine">
              {{ 'metadataLayers.combinedValue' | translate }}
              <textarea dir="ltr" rows="3" [ngModel]="combined()" (ngModelChange)="combined.set($event)"></textarea>
            </label>
          }

          <div class="mc-actions">
            <button type="button" (click)="resolve(c, 'keep_customer')" [disabled]="busy()">
              {{ 'metadataLayers.choices.keep_customer' | translate }}
            </button>
            <button type="button" (click)="resolve(c, 'take_platform')" [disabled]="busy()">
              {{ 'metadataLayers.choices.take_platform' | translate }}
            </button>
            @if (combining() === c.id) {
              <button type="button" (click)="resolve(c, 'combine')" [disabled]="busy()">
                {{ 'metadataLayers.applyCombined' | translate }}
              </button>
            } @else {
              <button type="button" (click)="startCombine(c, null)" [disabled]="busy()">
                {{ 'metadataLayers.choices.combine' | translate }}
              </button>
            }
            <button type="button" (click)="ask(c)" [disabled]="busy()">{{ 'metadataLayers.askAgent' | translate }}</button>
            @if (proposals()[c.id]; as p) {
              @if (p.status === 'proposed') {
                <button type="button" (click)="useProposal(c, p)" [disabled]="busy()">
                  {{ 'metadataLayers.useProposal' | translate }}
                </button>
              }
            }
          </div>
        </article>
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .mc { display: flex; flex-direction: column; gap: 0.5rem; }
    .mc h3 { margin-block: 0; font-size: 1rem; }
    .mc-card { border: 1px solid var(--color-border); border-radius: 4px; padding: 0.5rem;
      display: flex; flex-direction: column; gap: 0.375rem; }
    .mc-head { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: baseline; }
    .mc-values { display: grid; grid-template-columns: max-content 1fr; gap: 0.125rem 0.75rem; margin: 0; font-size: 0.875rem; }
    .mc-values dt { color: var(--color-text-secondary); }
    .mc-values dd { margin: 0; }
    .mc-proposal { background: var(--color-bg-alt); padding: 0.375rem 0.5rem; border-radius: 4px; font-size: 0.875rem; }
    .mc-proposal p { margin-block: 0.125rem; }
    .mc-reasoning { white-space: pre-wrap; }
    .mc-combine { display: flex; flex-direction: column; gap: 0.125rem; font-size: 0.8125rem; }
    .mc-combine textarea { font-family: var(--font-mono, monospace); }
    .mc-actions { display: flex; flex-wrap: wrap; gap: 0.25rem; }
    .mc-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .mc-error { color: var(--color-danger); }
  `],
})
export class MetadataConflictsComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly conflicts = signal<LayerConflict[]>([]);
  readonly proposals = signal<Record<string, ConflictProposal>>({});
  /** The conflict whose combined value is being edited. */
  readonly combining = signal<string | null>(null);
  readonly combined = signal('');
  readonly error = signal<string | null>(null);
  readonly badJson = signal(false);
  readonly busy = signal(false);

  readonly show = showValue;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.getAllPages<LayerConflict>('/api/v1/admin/metadata/conflicts', { status: 'open' }).subscribe({
      next: conflicts => this.conflicts.set(conflicts),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  startCombine(conflict: LayerConflict, value: unknown): void {
    const seed = value ?? conflict.customer ?? conflict.new_platform;
    this.combining.set(conflict.id);
    this.combined.set(seed === null || seed === undefined ? '' : JSON.stringify(seed, null, 2));
  }

  resolve(conflict: LayerConflict, choice: ConflictChoice): void {
    this.badJson.set(false);
    let body: { choice: ConflictChoice; value?: unknown } = { choice };
    if (choice === 'combine') {
      try {
        body = { choice, value: JSON.parse(this.combined()) };
      } catch {
        this.badJson.set(true);
        return;
      }
    }
    this.busy.set(true);
    this.error.set(null);
    this.api.post<LayerConflict>(`/api/v1/admin/metadata/conflicts/${encodeURIComponent(conflict.id)}/resolve`, body)
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.combining.set(null);
          this.proposals.update(all => {
            const rest = { ...all };
            delete rest[conflict.id];
            return rest;
          });
          this.load();
        },
        error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
      });
  }

  /** Asks the agent for a proposal; shown beside the conflict, never applied. */
  ask(conflict: LayerConflict): void {
    this.busy.set(true);
    this.error.set(null);
    this.api.post<{ status: string; result?: ConflictProposal }>(
      `/api/v1/actions/${encodeURIComponent(PROPOSE_CONFLICT_ACTION)}/invoke`,
      { args: { conflict_id: conflict.id } },
    ).subscribe({
      next: outcome => {
        this.busy.set(false);
        const proposal: ConflictProposal = outcome.status === 'completed' && outcome.result
          ? outcome.result
          : { status: 'declined', reason: outcome.status, conflict_id: conflict.id };
        this.proposals.update(all => ({ ...all, [conflict.id]: proposal }));
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  /** The builder's click on the proposal: a combine opens the value to check first; keep or take resolves. */
  useProposal(conflict: LayerConflict, proposal: Extract<ConflictProposal, { status: 'proposed' }>): void {
    if (proposal.choice === 'combine') {
      this.startCombine(conflict, proposal.value);
    } else {
      this.resolve(conflict, proposal.choice);
    }
  }
}
