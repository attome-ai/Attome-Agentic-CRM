import { Injectable, Type, inject, signal } from '@angular/core';
import { SdkService } from '@attome/base';

/**
 * A12-T5: whether an entity's record pages open a published metadata form
 * (`forms.runtime_entities`, `GET /api/v1/model/entities/{entity}/runtime-form`)
 * instead of its hand-written form. Asked once per entity per session; the
 * renderer itself loads only when an entity is switched.
 */
@Injectable({ providedIn: 'root' })
export class RuntimeFormSwitch {
  private readonly sdk = inject(SdkService);
  /** Entity to its form id, `null` when not switched; absent while unknown. */
  private readonly forms = signal<ReadonlyMap<string, string | null>>(new Map());
  private readonly asked = new Set<string>();
  /** The metadata form renderer, once loaded. */
  readonly renderer = signal<Type<unknown> | null>(null);

  /** The entity's form id, `null` when it keeps its own form, `undefined` until known. */
  formFor(entity: string): string | null | undefined {
    const known = this.forms().get(entity);
    if (known !== undefined || this.asked.has(entity)) return known;
    this.asked.add(entity);
    this.sdk.get<{ form_id: string }>(`/api/v1/model/entities/${encodeURIComponent(entity)}/runtime-form`).subscribe({
      next: answer => {
        const form = typeof answer?.form_id === 'string' ? answer.form_id : null;
        this.set(entity, form);
        if (form) void this.loadRenderer();
      },
      // Not switched (404), or not answerable: the entity keeps its form.
      error: () => this.set(entity, null),
    });
    return undefined;
  }

  private set(entity: string, form: string | null): void {
    this.forms.update(map => new Map(map).set(entity, form));
  }

  private async loadRenderer(): Promise<void> {
    if (this.renderer()) return;
    const m = await import('@attome/xrm/model');
    this.renderer.set(m.FormRendererComponent as Type<unknown>);
  }
}
