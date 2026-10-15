import { Injectable, Injector, effect, inject, untracked } from '@angular/core';

import { ApiService } from './api.service';
import { Lang, LangService } from './lang.service';

/**
 * B20-T3: a deployment's rewordings of built-in interface text
 * (`GET /api/v1/i18n/overrides`), laid over the product catalogue for the
 * current language and again whenever the language changes. Started by the
 * signed-in shell; a failed read leaves the built-in wording.
 */
@Injectable({ providedIn: 'root' })
export class UiTextOverrides {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  private readonly injector = inject(Injector);
  private started = false;

  start(): void {
    if (this.started) return;
    this.started = true;
    effect(() => {
      const lang = this.lang.current();
      untracked(() => this.load(lang));
    }, { injector: this.injector });
  }

  load(lang: Lang): void {
    this.api.get<{ texts: Record<string, string> }>('/api/v1/i18n/overrides', { locale: lang }).subscribe({
      next: overrides => this.lang.applyOverrides(lang, overrides.texts ?? {}),
      error: () => undefined,
    });
  }
}
