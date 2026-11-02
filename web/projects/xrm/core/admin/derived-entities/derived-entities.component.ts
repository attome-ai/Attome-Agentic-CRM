import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, SdkService, TranslatePipe } from '@attome/base';

/** A derived entity as `/api/v1/admin/derived-entities` lists it. */
export interface DerivedEntityDef {
  name: string;
  anchor: string;
  condition: string;
  /** `live` or `stored`. */
  mode: string;
}

/** What a condition selects (`POST .../preview`). */
export interface DerivedPreview {
  matching: number;
  entering: number;
  leaving: number | null;
  sample: { id: string; name: string | null }[];
}

/**
 * A26-T5: the derived entity designer. A derived entity is the anchor
 * entity's records that match a condition over its own fields, read-only
 * (A26-T1). Builders list them, write or change one with a preview of what
 * it selects (the cost panel: how many records, and how soon membership
 * follows a change), save, delete, and resume one the surge guard paused.
 * Logical CSS only.
 */
@Component({
  selector: 'xrm-derived-entities',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="de">
      <h3>{{ 'derivedEntitiesPage.title' | translate }}</h3>
      <p class="de-muted">{{ 'derivedEntitiesPage.intro' | translate }}</p>
      @if (error(); as message) { <p class="de-error" role="alert" dir="auto">{{ message }}</p> }

      <form class="de-form" data-testid="de-form" (submit)="$event.preventDefault(); save()">
        <label>{{ 'derivedEntitiesPage.name' | translate }}
          <input dir="ltr" name="name" [value]="draft().name" (input)="set('name', $any($event.target).value)" />
        </label>
        <label>{{ 'derivedEntitiesPage.anchor' | translate }}
          <input dir="ltr" name="anchor" [value]="draft().anchor" (input)="set('anchor', $any($event.target).value)" />
        </label>
        <label class="de-wide">{{ 'derivedEntitiesPage.condition' | translate }}
          <textarea dir="ltr" name="condition" rows="3" [value]="draft().condition"
                    (input)="set('condition', $any($event.target).value)"></textarea>
        </label>
        <label>{{ 'derivedEntitiesPage.mode' | translate }}
          <select name="mode" [value]="draft().mode" (change)="set('mode', $any($event.target).value)">
            <option value="live">{{ 'derivedEntitiesPage.modeLive' | translate }}</option>
            <option value="stored">{{ 'derivedEntitiesPage.modeStored' | translate }}</option>
          </select>
        </label>
        <div class="de-toolbar">
          <button type="button" data-testid="de-preview" (click)="previewDraft()" [disabled]="busy()">
            {{ 'derivedEntitiesPage.preview' | translate }}
          </button>
          <button type="submit" [disabled]="busy()">{{ 'derivedEntitiesPage.save' | translate }}</button>
          <button type="button" (click)="reset()">{{ 'derivedEntitiesPage.new' | translate }}</button>
        </div>
      </form>

      @if (preview(); as p) {
        <div class="de-cost" data-testid="de-cost" role="status">
          <p>{{ 'derivedEntitiesPage.matching' | translate: { count: p.matching } }}</p>
          <p>{{ 'derivedEntitiesPage.entering' | translate: { count: p.entering } }}
            @if (p.leaving !== null) { · {{ 'derivedEntitiesPage.leaving' | translate: { count: p.leaving } }} }
          </p>
          <p class="de-muted">
            {{ (draft().mode === 'stored' ? 'derivedEntitiesPage.costStored' : 'derivedEntitiesPage.costLive') | translate }}
          </p>
          @if (p.sample.length) {
            <ul class="de-sample">
              @for (m of p.sample; track m.id) { <li dir="auto">{{ m.name || m.id }}</li> }
            </ul>
          }
        </div>
      }

      @if (items().length === 0) {
        <p class="de-muted">{{ 'derivedEntitiesPage.none' | translate }}</p>
      } @else {
        <table class="de-table">
          <thead>
            <tr>
              <th scope="col">{{ 'derivedEntitiesPage.name' | translate }}</th>
              <th scope="col">{{ 'derivedEntitiesPage.anchor' | translate }}</th>
              <th scope="col">{{ 'derivedEntitiesPage.condition' | translate }}</th>
              <th scope="col">{{ 'derivedEntitiesPage.mode' | translate }}</th>
              <th scope="col"><span class="de-sr">{{ 'derivedEntitiesPage.actions' | translate }}</span></th>
            </tr>
          </thead>
          <tbody>
            @for (d of items(); track d.name) {
              <tr [attr.data-derived]="d.name">
                <td dir="ltr">{{ d.name }}</td>
                <td dir="ltr">{{ d.anchor }}</td>
                <td dir="ltr"><code>{{ d.condition }}</code></td>
                <td>{{ (d.mode === 'stored' ? 'derivedEntitiesPage.modeStored' : 'derivedEntitiesPage.modeLive') | translate }}</td>
                <td class="de-actions">
                  <button type="button" (click)="edit(d)">{{ 'derivedEntitiesPage.edit' | translate }}</button>
                  @if (d.mode === 'stored') {
                    <button type="button" (click)="resume(d)" [disabled]="busy()">{{ 'derivedEntitiesPage.resume' | translate }}</button>
                  }
                  <button type="button" (click)="remove(d)" [disabled]="busy()">{{ 'derivedEntitiesPage.delete' | translate }}</button>
                </td>
              </tr>
            }
          </tbody>
        </table>
      }
      @if (notice(); as n) { <p class="de-muted" role="status">{{ n }}</p> }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .de { display: flex; flex-direction: column; gap: 0.5rem; }
    .de h3 { margin-block: 0; font-size: 1rem; }
    .de-form { display: grid; grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr)); gap: 0.5rem; }
    .de-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.8125rem; }
    .de-wide { grid-column: 1 / -1; }
    .de-toolbar { display: flex; gap: 0.5rem; grid-column: 1 / -1; }
    .de-cost { border: 1px solid var(--color-border); border-radius: 6px; padding-block: 0.5rem; padding-inline: 0.75rem; }
    .de-cost p { margin-block: 0.125rem; }
    .de-sample { margin-block: 0.25rem; padding-inline-start: 1.25rem; font-size: 0.8125rem; }
    .de-table { inline-size: 100%; border-collapse: collapse; font-size: 0.875rem; }
    .de-table th, .de-table td { text-align: start; padding-block: 0.25rem; padding-inline: 0.5rem;
      border-block-end: 1px solid var(--color-border); vertical-align: top; }
    .de-actions { display: flex; flex-wrap: wrap; gap: 0.25rem; }
    .de-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .de-error { color: var(--color-danger); }
    .de-sr { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip-path: inset(50%); }
  `],
})
export class DerivedEntitiesComponent implements OnInit {
  private readonly sdk = inject(SdkService);

  readonly items = signal<DerivedEntityDef[]>([]);
  readonly draft = signal<DerivedEntityDef>({ name: '', anchor: '', condition: '', mode: 'live' });
  readonly preview = signal<DerivedPreview | null>(null);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly busy = signal(false);

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.sdk.getAllPages<DerivedEntityDef>('/api/v1/admin/derived-entities').subscribe({
      next: items => this.items.set(items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  set(field: keyof DerivedEntityDef, value: string): void {
    this.draft.update(d => ({ ...d, [field]: value }));
    this.preview.set(null);
  }

  edit(def: DerivedEntityDef): void {
    this.draft.set({ ...def });
    this.preview.set(null);
  }

  reset(): void {
    this.draft.set({ name: '', anchor: '', condition: '', mode: 'live' });
    this.preview.set(null);
  }

  previewDraft(): void {
    const d = this.draft();
    this.busy.set(true);
    this.error.set(null);
    this.sdk.post<DerivedPreview>('/api/v1/admin/derived-entities/preview', { body: {
      name: d.name.trim() || undefined, anchor: d.anchor.trim(), condition: d.condition,
    } }).subscribe({
      next: p => { this.busy.set(false); this.preview.set(p); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  save(): void {
    const d = this.draft();
    if (!d.name.trim()) return;
    this.busy.set(true);
    this.error.set(null);
    this.sdk.put<DerivedEntityDef>(`/api/v1/admin/derived-entities/${encodeURIComponent(d.name.trim())}`, { body: {
      anchor: d.anchor.trim(), condition: d.condition, mode: d.mode,
    } }).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  remove(def: DerivedEntityDef): void {
    this.busy.set(true);
    this.sdk.delete(`/api/v1/admin/derived-entities/${encodeURIComponent(def.name)}`).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  resume(def: DerivedEntityDef): void {
    this.busy.set(true);
    this.error.set(null);
    this.sdk.post<{ entered: number; left: number }>(
      `/api/v1/admin/derived-entities/${encodeURIComponent(def.name)}/resume`, { body: null },
    ).subscribe({
      next: r => { this.busy.set(false); this.notice.set(`${def.name}: +${r.entered} / −${r.left}`); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
