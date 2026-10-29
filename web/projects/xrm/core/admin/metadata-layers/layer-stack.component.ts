import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

import { showValue } from './metadata-layers.model';
import type { LayeredKind, PropertyStack, ResetResult } from './metadata-layers.model';

/**
 * Y11-T15: where an entity's or a field's settings come from. Per property,
 * the value each layer sets (platform, each app in install order, the
 * customer) and the one that applies. A customised property can be reset to
 * what the layers below give it: the reset is previewed first, applied only
 * on a second click, and can be undone once. Logical CSS only.
 */
@Component({
  selector: 'xrm-layer-stack',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <section class="ls">
      <h3>{{ 'metadataLayers.stackTitle' | translate }}</h3>
      <p class="ls-muted">{{ 'metadataLayers.stackIntro' | translate }}</p>

      <form class="ls-pick" (ngSubmit)="load()">
        <label>
          {{ 'metadataLayers.kind' | translate }}
          <select name="kind" [ngModel]="kind()" (ngModelChange)="kind.set($event)">
            <option value="entity">{{ 'metadataLayers.kinds.entity' | translate }}</option>
            <option value="attribute">{{ 'metadataLayers.kinds.attribute' | translate }}</option>
          </select>
        </label>
        <label>
          {{ 'metadataLayers.key' | translate }}
          <input name="key" dir="ltr" [ngModel]="key()" (ngModelChange)="key.set($event)"
                 [placeholder]="(kind() === 'entity' ? 'metadataLayers.keyEntity' : 'metadataLayers.keyAttribute') | translate" />
        </label>
        <button type="submit" [disabled]="busy() || !key().trim()">{{ 'metadataLayers.show' | translate }}</button>
      </form>

      @if (error(); as message) { <p class="ls-error" role="alert">{{ message }}</p> }

      @if (undoId(); as id) {
        <p class="ls-done" role="status">
          {{ 'metadataLayers.resetDone' | translate }}
          <button type="button" (click)="undo(id)" [disabled]="busy()">{{ 'metadataLayers.undo' | translate }}</button>
        </p>
      }

      @if (preview(); as p) {
        <div class="ls-preview" role="region" [attr.aria-label]="'metadataLayers.previewTitle' | translate">
          <h4>{{ 'metadataLayers.previewTitle' | translate }}</h4>
          <table class="ls-table">
            <thead><tr>
              <th scope="col">{{ 'metadataLayers.property' | translate }}</th>
              <th scope="col">{{ 'metadataLayers.now' | translate }}</th>
              <th scope="col">{{ 'metadataLayers.after' | translate }}</th>
            </tr></thead>
            <tbody>
              @for (c of p.changes; track c.property) {
                <tr [attr.data-change]="c.property">
                  <td dir="ltr">{{ c.property }}</td>
                  <td dir="auto">{{ show(c.current) }}</td>
                  <td dir="auto">
                    @if (c.after === null) { <span class="ls-muted">{{ 'metadataLayers.unchanged' | translate }}</span> }
                    @else { {{ show(c.after) }} }
                  </td>
                </tr>
              }
            </tbody>
          </table>
          <div class="ls-actions">
            <button type="button" class="ls-confirm" (click)="confirmReset()" [disabled]="busy()">
              {{ 'metadataLayers.confirmReset' | translate }}
            </button>
            <button type="button" (click)="cancelPreview()">{{ 'metadataLayers.cancel' | translate }}</button>
          </div>
        </div>
      }

      @if (loaded()) {
        @if (stack().length === 0) {
          <p class="ls-muted">{{ 'metadataLayers.noLayers' | translate }}</p>
        } @else {
          <div class="ls-actions">
            <button type="button" (click)="previewReset(null)" [disabled]="busy() || !hasCustomised()">
              {{ 'metadataLayers.resetAll' | translate }}
            </button>
          </div>
          <table class="ls-table">
            <thead><tr>
              <th scope="col">{{ 'metadataLayers.property' | translate }}</th>
              <th scope="col">{{ 'metadataLayers.values' | translate }}</th>
              <th scope="col">{{ 'metadataLayers.winner' | translate }}</th>
              <th scope="col"><span class="ls-sr">{{ 'metadataLayers.actions' | translate }}</span></th>
            </tr></thead>
            <tbody>
              @for (p of stack(); track p.property) {
                <tr [attr.data-property]="p.property">
                  <td dir="ltr">{{ p.property }}</td>
                  <td>
                    <ul class="ls-values">
                      @for (v of p.values; track $index) {
                        <li [class.ls-wins]="$last" [attr.data-layer]="v.layer">
                          <span class="ls-layer">{{ ('metadataLayers.layers.' + v.layer) | translate }}@if (v.app) { · {{ v.app }} }</span>
                          <span dir="auto">{{ show(v.value) }}</span>
                        </li>
                      }
                    </ul>
                  </td>
                  <td class="ls-winner">{{ ('metadataLayers.layers.' + p.winner) | translate }}</td>
                  <td>
                    @if (p.winner === 'customer') {
                      <button type="button" (click)="previewReset(p.property)" [disabled]="busy()">
                        {{ 'metadataLayers.reset' | translate }}
                      </button>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        }
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .ls { display: flex; flex-direction: column; gap: 0.5rem; }
    .ls h3 { margin-block: 0; font-size: 1rem; }
    .ls h4 { margin-block: 0 0.25rem; font-size: 0.875rem; }
    .ls-pick { display: flex; flex-wrap: wrap; align-items: end; gap: 0.5rem; }
    .ls-pick label { display: flex; flex-direction: column; gap: 0.125rem; font-size: 0.8125rem; }
    .ls-table { inline-size: 100%; border-collapse: collapse; font-size: 0.875rem; }
    .ls-table th, .ls-table td { text-align: start; padding-block: 0.25rem; padding-inline: 0.5rem;
      border-block-end: 1px solid var(--color-border); vertical-align: top; }
    .ls-values { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.125rem; }
    .ls-values li { display: flex; gap: 0.5rem; }
    .ls-layer { color: var(--color-text-secondary); min-inline-size: 7rem; }
    .ls-wins { font-weight: 600; }
    .ls-winner { font-weight: 600; }
    .ls-preview { padding: 0.5rem; border: 1px solid var(--color-border); border-radius: 4px; background: var(--color-bg-alt); }
    .ls-actions { display: flex; gap: 0.5rem; }
    .ls-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .ls-error { color: var(--color-danger); }
    .ls-done { color: var(--color-success); display: flex; gap: 0.5rem; align-items: center; }
    .ls-sr { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip-path: inset(50%); }
  `],
})
export class LayerStackComponent {
  private readonly api = inject(ApiService);

  readonly kind = signal<LayeredKind>('entity');
  readonly key = signal('');
  readonly stack = signal<PropertyStack[]>([]);
  readonly loaded = signal(false);
  readonly preview = signal<ResetResult | null>(null);
  /** The properties the open preview resets; `null` for every customised one. */
  private previewFor: string[] | null = null;
  readonly undoId = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);

  readonly show = showValue;

  private base(): string {
    return `/api/v1/admin/metadata/${this.kind()}/${encodeURIComponent(this.key().trim())}`;
  }

  hasCustomised(): boolean {
    return this.stack().some(p => p.winner === 'customer');
  }

  load(): void {
    if (!this.key().trim()) return;
    this.busy.set(true);
    this.error.set(null);
    this.preview.set(null);
    this.api.get<{ items: PropertyStack[] }>(`${this.base()}/layers`).subscribe({
      next: page => { this.busy.set(false); this.stack.set(page.items); this.loaded.set(true); },
      error: (e: ApiError) => { this.busy.set(false); this.loaded.set(false); this.error.set(e.message); },
    });
  }

  /** Asks what a reset would change; nothing changes until `confirmReset`. */
  previewReset(property: string | null): void {
    this.busy.set(true);
    this.error.set(null);
    this.undoId.set(null);
    this.previewFor = property === null ? null : [property];
    const body = this.previewFor === null ? {} : { properties: this.previewFor };
    this.api.post<ResetResult>(`${this.base()}/reset?preview=true`, body).subscribe({
      next: result => { this.busy.set(false); this.preview.set(result); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  cancelPreview(): void {
    this.preview.set(null);
  }

  confirmReset(): void {
    const body = this.previewFor === null ? {} : { properties: this.previewFor };
    this.busy.set(true);
    this.api.post<ResetResult>(`${this.base()}/reset`, body).subscribe({
      next: result => {
        this.busy.set(false);
        this.preview.set(null);
        this.undoId.set(result.reset_id);
        this.load();
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  undo(resetId: string): void {
    this.busy.set(true);
    this.api.post<void>(`/api/v1/admin/metadata/resets/${encodeURIComponent(resetId)}/undo`, null).subscribe({
      next: () => { this.busy.set(false); this.undoId.set(null); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
