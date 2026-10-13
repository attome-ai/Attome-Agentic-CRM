import { Directive, TemplateRef, inject, input } from '@angular/core';

/**
 * D-773 — one custom tab's panel content inside `<xrm-base-form>`:
 * `<ng-template xrmTab="versions">…</ng-template>`. The id must match a tab the
 * form's `defineTabs()` declares; the base form renders the panel (id, role,
 * `aria-labelledby`, `hidden`) and stamps this template into it.
 */
@Directive({ selector: 'ng-template[xrmTab]', standalone: true })
export class XrmTabDirective {
  readonly xrmTab = input.required<string>();
  readonly template = inject<TemplateRef<unknown>>(TemplateRef);
}
