import { NgTemplateOutlet } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, contentChildren, inject, input } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import { XRM_FIELD_POLICY, XrmFieldPolicy } from '../../business-rules/field-policy';
import { DuplicateBannerComponent } from '../../duplicate-banner/duplicate-banner.component';
import { PredictionBannerComponent } from '../../prediction-banner/prediction-banner.component';
import { RecordChangedBannerComponent } from '../../record-changed-banner/record-changed-banner.component';
import { RecordAccessActionsComponent } from '../../record-access/record-access-actions.component';
import { RecordTabPanelsComponent } from '../../record-tabs/record-tab-panels.component';
import { RemindMeComponent } from '../../reminders/remind-me.component';
import { FollowButtonComponent } from '../../follow-button/follow-button.component';
import { RecordTagsComponent } from '../../record-tags/record-tags.component';
import { RecordAncestorsComponent } from '../../record-tree/record-ancestors.component';
import { EngineFormBase } from '../xrm-form.base';
import { XrmTabDirective } from './xrm-tab.directive';

/**
 * D-773 — the template half of the base form. Every entity form extends
 * `EngineFormBase` (behaviour) and wraps its own content in this component
 * (the shared frame and every platform feature), because an Angular
 * component inherits its parent's code but not its template:
 *
 * ```html
 * <xrm-base-form [form]="this" [formGroup]="form()">
 *   <ng-template xrmTab="details">…this form's own sections and fields…</ng-template>
 *   <ng-template xrmTab="versions">…</ng-template>   <!-- one per custom tab -->
 *   <div xrmHeaderTitle>…</div>            <!-- replaces breadcrumb + title, with [customTitle]="true" -->
 *   <span xrmHeaderMeta>…</span>            <!-- under the title -->
 *   <button xrmHeaderActions>…</button>     <!-- before Back -->
 *   <div xrmOperations>…</div>              <!-- between the banners and the tabs -->
 * </xrm-base-form>
 * ```
 *
 * `[formGroup]` sits on this element, in the form's own template, so the
 * projected fields' `ControlContainer` lookups (which walk the template that
 * declares them) find it.
 *
 * Tab bodies are `<ng-template xrmTab>`, never plain projected content:
 * projected content is created at once, while the schema is still loading
 * and the form group is still empty, so a static `formControlName` there
 * would throw. A template is stamped only after the schema has loaded.
 * Record tabs render through `<xrm-record-tab-panels>`.
 *
 * Holds no state: it reads the host form's signals and calls its methods.
 * A platform feature added here reaches every form.
 *
 * D-789 section 5: provides `XRM_FIELD_POLICY` (the business-rule locks,
 * live rule messages and save refusals of the host form) to its content, so
 * every projected `attome-field-input` and `*xrmFieldVisible` hides or locks
 * itself. Content projected into this element resolves its providers
 * (`providers`, not `viewProviders`), as it already resolves the
 * `FormGroupDirective` on this element.
 */
@Component({
  selector: 'xrm-base-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    RecordAncestorsComponent,
    NgTemplateOutlet, TranslatePipe, DuplicateBannerComponent, PredictionBannerComponent,
    RecordChangedBannerComponent,
    RecordAccessActionsComponent, RecordTabPanelsComponent, RemindMeComponent, FollowButtonComponent, RecordTagsComponent,
  ],
  styleUrls: ['../../../../styles/xrm-form.css', './xrm-base-form.component.css'],
  templateUrl: './xrm-base-form.component.html',
  providers: [{ provide: XRM_FIELD_POLICY, useFactory: fieldPolicyOfBaseForm }],
})
export class XrmBaseFormComponent {
  /** The host form (`[form]="this"`). */
  readonly form = input.required<EngineFormBase>();
  /** Prefix of the tab and panel ids (`<prefix>-tab-<id>`, `<prefix>-panel-<id>`). */
  readonly idPrefix = input('entity');
  /** Render `<xrm-record-tab-panels>` for the platform record tabs. */
  readonly recordTabs = input(true);
  /** An extra reason the Save button is disabled (e.g. a deactivated account). */
  readonly saveDisabled = input(false);
  /** Catalog key for the idle Save label; defaults to Update/Create. */
  readonly saveLabel = input<string | null>(null);
  /** A read-only form (e.g. API keys, D-535): no Save button, no Assign/Share. */
  readonly readOnly = input(false);
  /** Replace the default breadcrumb and "Edit/New <entity>" title with the
   * form's own `[xrmHeaderTitle]` content (e.g. an identity header). */
  readonly customTitle = input(false);

  private readonly tabTemplates = contentChildren(XrmTabDirective);

  /** The form's own tab bodies: `xrmTab` templates whose id `defineTabs()` declared. */
  readonly tabPanels = computed(() => {
    const declared = new Set(this.form().tabs().map(t => t.id));
    return this.tabTemplates().filter(t => declared.has(t.xrmTab()));
  });

  /** U7 Phase A — the one record the header's Assign/Share act on. */
  readonly accessRecordIds = computed<readonly string[]>(() => {
    const id = this.form().id();
    return id ? [id] : [];
  });

  panelId(tab: string): string { return `${this.idPrefix()}-panel-${tab}`; }
  tabId(tab: string): string { return `${this.idPrefix()}-tab-${tab}`; }

  /** An owner or share changed: re-read the record (its owner and
   * `row_version` moved) unless the operator has unsaved edits — those keep
   * the ordinary conflict flow on their next save instead of being lost. */
  onAccessChanged(): void {
    const f = this.form();
    if (!f.form().dirty) f.reload();
  }

  /** Save on this form's own submit only. A record-tab panel with its own
   * `<form>` (Activities' add form) bubbles its submit up to here; that must
   * not also save the host record. */
  submit(event: Event): void {
    if (event.target !== event.currentTarget) return;
    event.preventDefault();
    this.form().save();
  }
}

/** The host form's business-rule state, read lazily so every call tracks its signals. */
function fieldPolicyOfBaseForm(): XrmFieldPolicy {
  const host = inject(XrmBaseFormComponent);
  return {
    lock:           name => host.form().fieldLock(name),
    ruleErrors:     name => host.form().ruleMessages(name),
    serverError:    name => host.form().serverFieldErrors().get(name) ?? null,
    requiredLocked: name => host.form().isRequiredLocked(name),
    value:          name => host.form().recordValue()[name],
  };
}
