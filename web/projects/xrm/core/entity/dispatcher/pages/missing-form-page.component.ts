import { ChangeDetectionStrategy, Component, OnInit, input, isDevMode } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslatePipe } from '@attome/base';
import { entityListRoute } from '@attome/xrm/core/entity';

/**
 * What `EntityRouterComponent` shows for a form route whose entity has no
 * registered `formComponent`. There is no generic, metadata-driven form any
 * more (SYSTEM-CHANGES.md Topic 14, FORMS-IN-CODE-PLAN.md §6 step 2): every
 * entity has its own form in code, and `entity-form-coverage.spec.ts` fails
 * when one is missing — so reaching this page means a registration or a
 * loader-table row (`src/app/attome-metadata-form-loaders.ts`) is missing, or the
 * URL names no real entity. It says so plainly instead of rendering a guess,
 * and logs a `console.error` so the gap is visible in the client error trail.
 */
@Component({
  selector:   'xrm-missing-form-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [RouterLink, TranslatePipe],
  styleUrls:  ['../../../../styles/xrm-form.css'],
  styles: [`
    :host { display: block; padding: 24px; }
    .xf-missing-form { display: flex; flex-direction: column; gap: 12px; max-width: 640px; }
    .xf-missing-form h1 { margin: 0; font-size: 18px; }
    .xf-missing-form p { margin: 0; }
  `],
  template: `
    <section class="xf-missing-form" data-testid="missing-form">
      <h1>{{ 'xrmForm.noFormTitle' | translate }}</h1>
      <div class="xf-error-banner" role="alert">
        <i class="las la-exclamation-triangle" aria-hidden="true"></i>
        <p>{{ 'xrmForm.noFormMessage' | translate: { name: name() } }}</p>
      </div>
      @if (devMode) {
        <p class="xf-empty">{{ 'xrmForm.noFormHint' | translate }}</p>
      }
      <a [routerLink]="listRoute()">{{ 'xrmForm.backToList' | translate }}</a>
    </section>
  `,
})
export class MissingFormPageComponent implements OnInit {
  /** The entity logical name the route named. */
  readonly name = input('');
  /** Passed by the router like any form's input; unused here. */
  readonly id = input<string | null>(null);

  protected readonly devMode = isDevMode();

  ngOnInit(): void {
    console.error(`No form is registered for entity "${this.name()}" (FORMS-IN-CODE-PLAN.md).`);
  }

  protected listRoute(): string[] {
    return entityListRoute(this.name());
  }
}
