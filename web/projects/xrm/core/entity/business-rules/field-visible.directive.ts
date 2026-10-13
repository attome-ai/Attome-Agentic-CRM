import { Directive, effect, inject, input, TemplateRef, ViewContainerRef } from '@angular/core';
import { XRM_FIELD_POLICY } from './field-policy';

/**
 * D-789 §5 — a form field rendered **outside** `<attome-field-input>` (a
 * bespoke control in a hand-written form) is wrapped in
 * `*xrmFieldVisible="'field_name'"`, so a business rule's `hidden` policy
 * removes it exactly as `attome-field-input` removes itself. A `disabled`
 * policy needs nothing here: `EngineFormBase` disables the control, and a
 * `formControlName` input renders disabled on its own.
 *
 * Reads `XRM_FIELD_POLICY` from the enclosing `<xrm-base-form>`; outside one
 * (or with no rules) the content is always shown. Presentation only — the
 * server refuses a write that changes a locked field.
 */
@Directive({ selector: '[xrmFieldVisible]', standalone: true })
export class XrmFieldVisibleDirective {
  /** The field's logical name. */
  readonly xrmFieldVisible = input.required<string>();

  private readonly template = inject<TemplateRef<unknown>>(TemplateRef);
  private readonly vcr = inject(ViewContainerRef);
  private readonly policy = inject(XRM_FIELD_POLICY, { optional: true });
  private shown = false;

  constructor() {
    effect(() => {
      const hidden = this.policy?.lock(this.xrmFieldVisible())?.effect === 'hidden';
      if (!hidden && !this.shown) {
        this.vcr.createEmbeddedView(this.template);
        this.shown = true;
      } else if (hidden && this.shown) {
        this.vcr.clear();
        this.shown = false;
      }
    });
  }
}
