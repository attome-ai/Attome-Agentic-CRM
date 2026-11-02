import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, signal,
} from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { ApiService, LangService, TemplateRendererService, TranslatePipe } from '@attome/base';
import type { RulesSchema } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import { rulesSchemaOf } from '@attome/xrm/core/admin/expression-editor';

/** How long typing has to pause before a render. */
const DEBOUNCE_MS = 200;

/** A sample value per rule type, so a preview shows every field filled in. */
function sampleOf(type: string, label: string): unknown {
  if (type === 'number') return 1234.5;
  if (type === 'bool') return true;
  if (type === 'date') return '2026-01-31T09:00:00Z';
  if (type === 'text' || type === 'choice') return label;
  return null;
}

/**
 * Z13-T9: renders a template as it is typed, in the browser, with the server's
 * renderer on sample values. When the module cannot run (it failed to load, say)
 * and a record is named, it falls back to the server's preview route. The output
 * sits in a sandboxed frame, so a template's markup cannot reach the page.
 */
@Component({
  selector: 'attome-template-preview',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="preview" [attr.aria-label]="'templatePreview.title' | translate">
      <h3>{{ 'templatePreview.title' | translate }}</h3>
      @if (problem(); as problem) {
        <p class="problem" role="alert">{{ problem }}</p>
      } @else if (output(); as output) {
        <iframe
          sandbox=""
          [attr.title]="'templatePreview.title' | translate"
          [srcdoc]="output"></iframe>
      } @else {
        <p>{{ 'templatePreview.empty' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .preview { display: block; margin-top: 16px; }
    h3 { margin: 0 0 8px; font-size: 14px; }
    iframe { width: 100%; min-height: 240px; border: 1px solid var(--color-border); background: #fff; }
    .problem { color: var(--color-danger); white-space: pre-wrap; }
  `],
})
export class TemplatePreviewComponent {
  private readonly api = inject(ApiService);
  private readonly renderer = inject(TemplateRendererService);
  private readonly lang = inject(LangService);

  /** The template source. */
  readonly template = input('');
  /** The entity the template is for. */
  readonly entity = input('');
  /** A record to preview through the server when the browser cannot. */
  readonly recordId = input<string | null>(null);

  protected readonly output = signal('');
  protected readonly problem = signal('');
  private readonly schemaOfEntity = signal<EntitySchema | null>(null);
  private readonly rules = computed<RulesSchema>(() => {
    const schema = this.schemaOfEntity();
    return schema ? rulesSchemaOf(schema) : { fields: {} };
  });
  private timer?: ReturnType<typeof setTimeout>;
  private run = 0;

  constructor() {
    effect(() => {
      const entity = this.entity();
      if (!entity) return;
      firstValueFrom(this.api.get<EntitySchema>(`/api/v1/schema/${encodeURIComponent(entity)}`))
        .then(schema => this.schemaOfEntity.set(schema))
        .catch(() => this.schemaOfEntity.set(null));
    });
    effect(() => {
      const template = this.template();
      const rules = this.rules();
      clearTimeout(this.timer);
      this.timer = setTimeout(() => void this.render(template, rules), DEBOUNCE_MS);
    });
    inject(DestroyRef).onDestroy(() => clearTimeout(this.timer));
  }

  private sample(rules: RulesSchema): Record<string, unknown> {
    const labels = new Map(this.schemaOfEntity()?.fields.map(f => [f.name, f.display_name]));
    return Object.fromEntries(
      Object.entries(rules.fields ?? {}).map(([name, type]) => [
        name,
        sampleOf(type, labels.get(name) ?? name),
      ]),
    );
  }

  private async render(template: string, rules: RulesSchema): Promise<void> {
    const run = ++this.run;
    if (!template.trim()) {
      this.output.set('');
      this.problem.set('');
      return;
    }
    const locale = this.lang.intlLocale();
    try {
      const answer = await this.renderer.render(
        template,
        rules,
        { now: new Date().toISOString(), fields: this.sample(rules) },
        locale,
      );
      if (run !== this.run) return;
      this.output.set(answer.output ?? '');
      this.problem.set(answer.ok ? '' : (answer.diagnostics?.[0]?.message ?? ''));
    } catch {
      await this.renderOnServer(run, template, locale);
    }
  }

  /** The browser could not render: the server's route, when a record is named. */
  private async renderOnServer(run: number, template: string, language: string): Promise<void> {
    const record_id = this.recordId();
    if (!record_id) {
      if (run === this.run) this.problem.set(this.lang.translate('templatePreview.unavailable'));
      return;
    }
    try {
      const { rendered } = await firstValueFrom(this.api.post<{ rendered: string }>(
        '/api/v1/admin/templates/preview',
        { template, entity: this.entity(), record_id, language },
      ));
      if (run !== this.run) return;
      this.output.set(rendered);
      this.problem.set('');
    } catch {
      if (run === this.run) this.problem.set(this.lang.translate('templatePreview.unavailable'));
    }
  }
}
