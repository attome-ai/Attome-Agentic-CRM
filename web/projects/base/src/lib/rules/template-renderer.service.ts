import { Injectable, InjectionToken, inject } from '@angular/core';
import type { RulesContext, RulesDiagnostic, RulesSchema } from './rules-evaluator.service';

/**
 * Z13-T9: where the template renderer's WebAssembly comes from, a URL the
 * browser fetches (the host app copies the module to `/tmpl/`), or bytes (a
 * test reads them from disk).
 */
export const TEMPLATE_WASM_SOURCE = new InjectionToken<string | (() => Promise<BufferSource>)>(
  'TEMPLATE_WASM_SOURCE',
  { providedIn: 'root', factory: () => '/tmpl/attome_html_wasm_bg.wasm' },
);

/** The renderer's answer. */
export interface TemplateAnswer {
  ok: boolean;
  output?: string;
  diagnostics?: RulesDiagnostic[];
}

interface HtmlModule {
  default(init: { module_or_path: string | BufferSource }): Promise<unknown>;
  render(template: string, schema: string, context: string, locale: string, output: string): string;
}

/**
 * Z13-T9: the server's template renderer (attome-html), built to WebAssembly,
 * so a preview shows what the server will render without a round trip. The
 * module loads on first use.
 */
@Injectable({ providedIn: 'root' })
export class TemplateRendererService {
  private readonly source = inject(TEMPLATE_WASM_SOURCE);
  private module?: Promise<HtmlModule>;

  private load(): Promise<HtmlModule> {
    this.module ??= (import('./html-wasm/attome_html_wasm') as Promise<HtmlModule>).then(async m => {
      const source = this.source;
      await m.default({ module_or_path: typeof source === 'string' ? source : await source() });
      return m;
    });
    return this.module;
  }

  /** `template` rendered on `context` for `locale`, or the errors. */
  async render(
    template: string,
    schema: RulesSchema,
    context: RulesContext,
    locale: string,
    output: 'html' | 'text' = 'html',
  ): Promise<TemplateAnswer> {
    const m = await this.load();
    return JSON.parse(
      m.render(template, JSON.stringify(schema), JSON.stringify(context), locale, output),
    ) as TemplateAnswer;
  }
}
