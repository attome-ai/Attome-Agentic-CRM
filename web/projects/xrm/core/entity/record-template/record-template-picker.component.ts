import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import type { Page } from '@attome/base';

import { entityFormRoute } from '../services/entity-url.utils';

/** `attome_api::record_template_routes::TemplatePrompt`. */
export interface TemplatePrompt {
  field: string;
  label_en: string;
  label_ar: string | null;
  required: boolean;
}

/** `attome_api::record_template_routes::OfferedTemplate`. */
export interface OfferedTemplate {
  id: string;
  label_en: string;
  label_ar: string | null;
  prompts: TemplatePrompt[];
  children: number;
}

/** The required prompts still unanswered. */
export function missingAnswers(template: OfferedTemplate, answers: Record<string, string>): string[] {
  return template.prompts
    .filter(p => p.required && (answers[p.field] ?? '').trim() === '')
    .map(p => p.field);
}

/**
 * B8-T3 — "New from a template" beside the New button: the published
 * templates the caller may use for this entity (the server checks each
 * template's condition and the create right), a dialog for the template's
 * prompts, then the record (and its child records) created through the
 * template and opened. Renders nothing when no template is offered.
 */
@Component({
  selector: 'xrm-record-template-picker',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    @if (templates().length > 0) {
      <span class="rtp">
        <button type="button" class="btn btn-secondary" data-testid="rtp-open"
                [attr.aria-expanded]="open()" (click)="open.set(!open())">
          {{ 'recordTemplates.fromTemplate' | translate }}
        </button>
        @if (open()) {
          <ul class="rtp-menu" role="menu">
            @for (t of templates(); track t.id) {
              <li role="none">
                <button type="button" role="menuitem" data-testid="rtp-template" (click)="choose(t)">{{ label(t) }}</button>
              </li>
            }
          </ul>
        }
      </span>
    }
    @if (chosen(); as t) {
      <div class="rtp-dialog" role="dialog" aria-modal="true" [attr.aria-label]="label(t)" data-testid="rtp-dialog">
        <h3>{{ label(t) }}</h3>
        @for (p of t.prompts; track p.field) {
          <label>
            {{ promptLabel(p) }}@if (p.required) { * }
            <input type="text" dir="auto" [name]="p.field" [(ngModel)]="answers[p.field]" [attr.data-prompt]="p.field" />
          </label>
        }
        @if (t.children > 0) {
          <p class="rtp-note">{{ 'recordTemplates.children' | translate: { count: t.children } }}</p>
        }
        @if (error(); as message) {
          <p class="rtp-error" role="alert" data-testid="rtp-error">{{ message }}</p>
        }
        <div class="rtp-buttons">
          <button type="button" class="btn btn-primary" data-testid="rtp-create" [disabled]="busy()" (click)="create(t)">
            {{ 'recordTemplates.create' | translate }}
          </button>
          <button type="button" class="btn btn-secondary" (click)="chosen.set(null)">{{ 'recordTemplates.cancel' | translate }}</button>
        </div>
      </div>
    }
  `,
  styles: [`
    .rtp { position: relative; display: inline-block; }
    .rtp-menu { position: absolute; inset-inline-start: 0; z-index: 10; min-inline-size: 12rem; margin: 0; padding: 0.25rem; list-style: none; background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 0.375rem; }
    .rtp-menu button { inline-size: 100%; text-align: start; padding-block: 0.375rem; padding-inline: 0.5rem; background: none; border: 0; cursor: pointer; }
    .rtp-dialog { display: flex; flex-direction: column; gap: 0.75rem; margin-block: 0.75rem; padding: 1rem; border: 1px solid var(--color-border); border-radius: 0.5rem; max-inline-size: 32rem; background: var(--color-surface); }
    .rtp-dialog label { display: flex; flex-direction: column; gap: 0.25rem; }
    .rtp-buttons { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    .rtp-note { font-size: 0.8125rem; color: var(--color-text-secondary); }
    .rtp-error { color: var(--color-danger); }
  `],
})
export class RecordTemplatePickerComponent {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  private readonly router = inject(Router);

  /** The entity's logical name. */
  readonly entity = input.required<string>();
  /** The new record's type, when the list knows it. */
  readonly recordType = input<string | null>(null);

  readonly templates = signal<OfferedTemplate[]>([]);
  readonly open = signal(false);
  readonly chosen = signal<OfferedTemplate | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  answers: Record<string, string> = {};

  constructor() {
    effect(onCleanup => {
      const entity = this.entity();
      const type = this.recordType();
      this.templates.set([]);
      const params: Record<string, string> = { entity };
      if (type) params['type'] = type;
      const sub = this.api.get<Page<OfferedTemplate>>('/api/v1/record-templates', params).subscribe({
        next: page => this.templates.set(page.items ?? []),
        // No template offered (or no right to create): nothing to show.
        error: () => this.templates.set([]),
      });
      onCleanup(() => sub.unsubscribe());
    });
  }

  label(t: OfferedTemplate): string {
    return this.lang.current() === 'ar' && t.label_ar ? t.label_ar : t.label_en;
  }

  promptLabel(p: TemplatePrompt): string {
    return this.lang.current() === 'ar' && p.label_ar ? p.label_ar : p.label_en;
  }

  choose(t: OfferedTemplate): void {
    this.open.set(false);
    this.answers = {};
    this.error.set(null);
    if (t.prompts.length === 0 && t.children === 0) {
      this.create(t);
      return;
    }
    this.chosen.set(t);
  }

  create(t: OfferedTemplate): void {
    const missing = missingAnswers(t, this.answers);
    if (missing.length > 0) {
      this.error.set(this.lang.translate('recordTemplates.required', { fields: missing.join(', ') }));
      return;
    }
    const answers: Record<string, string> = {};
    for (const p of t.prompts) {
      const value = (this.answers[p.field] ?? '').trim();
      if (value !== '') answers[p.field] = value;
    }
    this.busy.set(true);
    this.api.post<{ entity: string; id: string }>(`/api/v1/record-templates/${t.id}/create`, { answers }).subscribe({
      next: created => {
        this.busy.set(false);
        this.chosen.set(null);
        void this.router.navigate(entityFormRoute(created.entity), { queryParams: { id: created.id } });
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}
