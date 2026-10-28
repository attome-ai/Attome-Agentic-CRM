import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `attome_ops::incidents::Incident`. */
export interface Incident {
  id: string;
  title_en: string;
  title_ar: string | null;
  audience: 'internal' | 'public';
  state: string;
  components: string[];
  impact: 'degraded' | 'partial' | 'major';
  started_at: string;
  resolved_at: string | null;
  published_at: string | null;
  auto_created: boolean;
  row_version: number;
}

/** `attome_ops::incidents::IncidentUpdate`. */
export interface IncidentUpdate {
  id: string;
  incident_id: string;
  stage: string;
  body_en: string;
  body_ar: string | null;
  corrects_update_id: string | null;
  published_at: string;
}

interface Page<T> { items: T[]; total: number; page: number; page_size: number }
interface StatusComponent { key: string; name_en: string; name_ar: string }

export const STAGES = ['investigating', 'identified', 'monitoring', 'resolved', 'note'] as const;
export const IMPACTS = ['degraded', 'partial', 'major'] as const;

/** An update to publish. */
export interface UpdateDraft { stage: string; body_en: string; body_ar: string; corrects_update_id: string | null }

/** Whether an update may be published: both languages written. Pure. */
export function canPublish(draft: UpdateDraft): boolean {
  return draft.body_en.trim().length > 0 && draft.body_ar.trim().length > 0;
}

/** Open incidents, or every incident when `withResolved`. Pure. */
export function visibleIncidents(items: Incident[], withResolved: boolean): Incident[] {
  return withResolved ? items : items.filter(i => !i.resolved_at);
}

/**
 * AB11-T9 — the incidents console: the incidents (open ones, or all), a new
 * draft, and for the chosen incident its updates and the editor for the next
 * one, English and Arabic side by side and both required. A published update
 * is never edited: each has a correction action, which publishes a new
 * update naming it.
 */
@Component({
  selector: 'attome-ops-incidents',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, LocalDatePipe],
  template: `
    <section class="oi-page">
      <h2>{{ 'ops.status.incidents' | translate }}</h2>
      @if (error(); as message) { <p class="oi-error" role="alert">{{ message }}</p> }

      <label class="oi-inline">
        <input type="checkbox" [ngModel]="withResolved()" (ngModelChange)="withResolved.set($event)" name="resolved" data-testid="oi-resolved" />
        {{ 'ops.status.showResolved' | translate }}
      </label>
      <ul class="oi-list" data-testid="oi-list">
        @for (i of shown(); track i.id) {
          <li>
            <button type="button" class="oi-pick" [class.oi-current]="i.id === selected()?.id" (click)="open(i.id)" [attr.data-incident]="i.id">
              <strong>{{ lang.current() === 'ar' && i.title_ar ? i.title_ar : i.title_en }}</strong>
              <span class="oi-tag">{{ 'ops.status.state.' + i.state | translate }}</span>
              <span class="oi-tag">{{ 'ops.status.impact.' + i.impact | translate }}</span>
              @if (i.auto_created) { <span class="oi-tag">{{ 'ops.status.automatic' | translate }}</span> }
            </button>
          </li>
        } @empty {
          <li>{{ 'ops.status.noIncidents' | translate }}</li>
        }
      </ul>

      <details class="oi-new">
        <summary>{{ 'ops.status.newDraft' | translate }}</summary>
        <div class="oi-pair">
          <label>{{ 'ops.status.titleEn' | translate }}<input dir="ltr" [(ngModel)]="newTitleEn" name="title_en" data-testid="oi-title-en" /></label>
          <label>{{ 'ops.status.titleAr' | translate }}<input dir="rtl" [(ngModel)]="newTitleAr" name="title_ar" /></label>
        </div>
        <label>{{ 'ops.status.impactLabel' | translate }}
          <select [(ngModel)]="newImpact" name="impact">
            @for (x of impacts; track x) { <option [value]="x">{{ 'ops.status.impact.' + x | translate }}</option> }
          </select>
        </label>
        <fieldset>
          <legend>{{ 'ops.status.components' | translate }}</legend>
          @for (c of components(); track c.key) {
            <label class="oi-inline">
              <input type="checkbox" [checked]="newComponents().includes(c.key)" (change)="toggleComponent(c.key)" />
              {{ lang.current() === 'ar' ? c.name_ar : c.name_en }}
            </label>
          }
        </fieldset>
        <button type="button" data-testid="oi-create" [disabled]="busy() || !newTitleEn.trim()" (click)="create()">{{ 'ops.status.createDraft' | translate }}</button>
      </details>

      @if (selected(); as inc) {
        <article class="oi-detail" data-testid="oi-detail">
          <h3>{{ inc.title_en }}</h3>
          <ol class="oi-updates">
            @for (u of updates(); track u.id) {
              <li [class.oi-correction]="u.corrects_update_id" [attr.data-update]="u.id">
                @if (u.corrects_update_id) { <span class="oi-tag">{{ 'ops.status.correction' | translate }}</span> }
                <span class="oi-tag">{{ 'ops.status.state.' + u.stage | translate }}</span>
                {{ u.published_at | localDate }}
                <p dir="ltr">{{ u.body_en }}</p>
                <p dir="rtl">{{ u.body_ar }}</p>
                <button type="button" class="oi-link" (click)="correct(u)" [attr.data-correct]="u.id">{{ 'ops.status.correct' | translate }}</button>
              </li>
            }
          </ol>

          @if (!inc.resolved_at || draft().corrects_update_id) {
            <div class="oi-editor" data-testid="oi-editor">
              @if (draft().corrects_update_id) {
                <p class="oi-note">{{ 'ops.status.correcting' | translate }}
                  <button type="button" class="oi-link" (click)="resetDraft()">{{ 'ops.status.cancel' | translate }}</button>
                </p>
              }
              <label>{{ 'ops.status.stage' | translate }}
                <select [ngModel]="draft().stage" (ngModelChange)="patchDraft({ stage: $event })" name="stage">
                  @for (s of stages; track s) { <option [value]="s">{{ 'ops.status.state.' + s | translate }}</option> }
                </select>
              </label>
              <div class="oi-pair">
                <label>{{ 'ops.status.bodyEn' | translate }}
                  <textarea dir="ltr" rows="4" [ngModel]="draft().body_en" (ngModelChange)="patchDraft({ body_en: $event })" name="body_en" data-testid="oi-body-en"></textarea>
                </label>
                <label>{{ 'ops.status.bodyAr' | translate }}
                  <textarea dir="rtl" rows="4" [ngModel]="draft().body_ar" (ngModelChange)="patchDraft({ body_ar: $event })" name="body_ar" data-testid="oi-body-ar"></textarea>
                </label>
              </div>
              @if (!publishable()) { <p class="oi-note" data-testid="oi-both">{{ 'ops.status.bothLanguages' | translate }}</p> }
              <button type="button" data-testid="oi-publish" [disabled]="busy() || !publishable()" (click)="publish(inc.id)">{{ 'ops.status.publish' | translate }}</button>
            </div>
          }
        </article>
      }
    </section>
  `,
  styles: [`
    .oi-page { padding-inline: 1rem; max-inline-size: 64rem; display: flex; flex-direction: column; gap: 0.75rem; }
    .oi-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 0.25rem; }
    .oi-pick { inline-size: 100%; text-align: start; display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; padding: 0.5rem; border: 1px solid var(--color-border); border-radius: 0.375rem; background: none; cursor: pointer; color: inherit; }
    .oi-current { border-color: var(--color-accent); }
    .oi-tag { font-size: 0.75rem; padding-inline: 0.375rem; border: 1px solid var(--color-border); border-radius: 0.25rem; }
    .oi-pair { display: grid; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); gap: 0.75rem; }
    .oi-pair label, .oi-editor label, .oi-new label { display: flex; flex-direction: column; gap: 0.25rem; }
    .oi-page .oi-inline { display: flex; flex-direction: row; align-items: center; gap: 0.5rem; }
    .oi-updates { padding-inline-start: 1.25rem; display: flex; flex-direction: column; gap: 0.5rem; }
    .oi-correction { margin-inline-start: 1rem; }
    .oi-editor, .oi-new { display: flex; flex-direction: column; gap: 0.5rem; }
    .oi-link { background: none; border: 0; padding: 0; color: var(--color-accent); cursor: pointer; }
    .oi-note { margin: 0; font-size: 0.875rem; }
    .oi-error { color: var(--color-danger); }
  `],
})
export class IncidentsComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly lang = inject(LangService);

  readonly stages = STAGES;
  readonly impacts = IMPACTS;

  readonly items = signal<Incident[]>([]);
  readonly withResolved = signal(false);
  readonly components = signal<StatusComponent[]>([]);
  readonly selected = signal<Incident | null>(null);
  readonly updates = signal<IncidentUpdate[]>([]);
  readonly draft = signal<UpdateDraft>({ stage: 'investigating', body_en: '', body_ar: '', corrects_update_id: null });
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly newComponents = signal<string[]>([]);
  newTitleEn = '';
  newTitleAr = '';
  newImpact = 'degraded';

  readonly shown = computed(() => visibleIncidents(this.items(), this.withResolved()));
  readonly publishable = computed(() => canPublish(this.draft()));

  ngOnInit(): void {
    this.load();
    this.api.get<{ components: StatusComponent[] }>('/api/v1/ops/status').subscribe({
      next: s => this.components.set(s?.components ?? []),
      error: () => undefined,
    });
  }

  load(): void {
    this.api.get<Page<Incident>>('/api/v1/ops/incidents', { page_size: '100' }).subscribe({
      next: page => this.items.set(page.items),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  open(id: string): void {
    this.api.get<Incident & { updates: IncidentUpdate[] }>(`/api/v1/ops/incidents/${encodeURIComponent(id)}`).subscribe({
      next: detail => {
        const { updates, ...incident } = detail;
        this.selected.set(incident);
        this.updates.set(updates);
        this.resetDraft();
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  toggleComponent(key: string): void {
    this.newComponents.update(list => (list.includes(key) ? list.filter(k => k !== key) : [...list, key]));
  }

  create(): void {
    this.busy.set(true);
    this.api.post<Incident>('/api/v1/ops/incidents', {
      title_en: this.newTitleEn.trim(),
      title_ar: this.newTitleAr.trim() || null,
      impact: this.newImpact,
      components: this.newComponents(),
    }).subscribe({
      next: incident => {
        this.busy.set(false);
        this.newTitleEn = '';
        this.newTitleAr = '';
        this.newComponents.set([]);
        this.items.update(list => [incident, ...list]);
        this.open(incident.id);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  patchDraft(change: Partial<UpdateDraft>): void {
    this.draft.update(d => ({ ...d, ...change }));
  }

  resetDraft(): void {
    this.draft.set({ stage: 'investigating', body_en: '', body_ar: '', corrects_update_id: null });
  }

  /** Starts a correction of `update`: a new update naming it, never an edit. */
  correct(update: IncidentUpdate): void {
    this.draft.set({ stage: 'note', body_en: update.body_en, body_ar: update.body_ar ?? '', corrects_update_id: update.id });
  }

  publish(incidentId: string): void {
    const draft = this.draft();
    if (!canPublish(draft)) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.post<IncidentUpdate>(`/api/v1/ops/incidents/${encodeURIComponent(incidentId)}/updates`, {
      stage: draft.stage,
      body_en: draft.body_en.trim(),
      body_ar: draft.body_ar.trim(),
      corrects_update_id: draft.corrects_update_id,
    }).subscribe({
      next: () => {
        this.busy.set(false);
        this.load();
        this.open(incidentId);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}
