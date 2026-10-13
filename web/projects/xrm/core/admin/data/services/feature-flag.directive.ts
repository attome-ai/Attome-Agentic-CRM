import { Directive, effect, inject, Input, TemplateRef, ViewContainerRef } from '@angular/core';

import { FeatureFlagsService } from './feature-flags.service';

/**
 * Structural directive companion to `FeatureFlagsService` (M95, D-430):
 * renders its host template only while the named flag evaluates on for the
 * current user, mirroring `*ngIf`'s shape.
 *
 * ```html
 * <div *xrmFeatureFlag="'core.beta_ui'">…</div>
 * ```
 *
 * Rendering convenience only, not a security boundary — see
 * `FeatureFlagsService`'s doc comment. Lazily triggers the first
 * `/api/v1/features` fetch via `ensureLoaded()` (idempotent across every
 * directive instance on a page) and re-evaluates whenever the service's
 * `flags` signal changes, so a page that calls `FeatureFlagsService.refresh()`
 * after an admin edit updates in place without a reload.
 */
@Directive({
  selector: '[xrmFeatureFlag]',
  standalone: true,
})
export class FeatureFlagDirective {
  private readonly templateRef = inject(TemplateRef<unknown>);
  private readonly viewContainer = inject(ViewContainerRef);
  private readonly features = inject(FeatureFlagsService);

  private key = '';
  private created = false;

  @Input({ required: true })
  set xrmFeatureFlag(key: string) {
    this.key = key;
    this.evaluate();
  }

  constructor() {
    this.features.ensureLoaded();
    effect(() => {
      this.features.flags(); // subscribe this effect to the signal
      this.evaluate();
    });
  }

  private evaluate(): void {
    const on = this.key !== '' && this.features.isOn(this.key);
    if (on && !this.created) {
      this.viewContainer.createEmbeddedView(this.templateRef);
      this.created = true;
    } else if (!on && this.created) {
      this.viewContainer.clear();
      this.created = false;
    }
  }
}
