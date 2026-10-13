import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormGroup, ReactiveFormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
// Type-only — erased at compile time, so importing from the parent
// `@attome/xrm/workflow` entry here (this form lives in the separate,
// lighter `workflow/registration` entry — see that entry's public-api.ts
// doc comment) costs nothing at runtime and creates no entry-to-entry
// dependency edge for ng-packagr to flag as circular. A *relative* reach
// into the parent entry's services/ folder was tried first and rejected:
// ng-packagr enforces each entry's rootDir strictly, so even a type-only
// relative import outside `workflow/registration/` fails the build (TS6059).
// The three HTTP calls below still go through ApiService directly rather
// than WorkflowAdminService, which would be a real (non-type-only) import.
import type { DefinitionDetail, VersionSummary } from '@attome/xrm/workflow';
import { XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs } from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';

/**
 * Form override for `workflow_definition` — the edit half of the
 * workflow UI, reached by clicking a row in the workflow list.
 *
 * Same shape as UserFormComponent (sectioned xf-* layout on top of
 * EngineFormBase's generic schema/record plumbing), plus two workflow-specific
 * rules the generic form can't know:
 *
 *  * `logicalname` is disabled once the record exists. It is the stable key
 *    triggers and `POST /api/v1/workflow/instances` resolve a workflow by
 *    (`instance_admin.rs`, `trigger_index.rs`), and the engine's own admin
 *    API deliberately offers no way to change it. A disabled control is
 *    excluded from `FormGroup.value`, so it is never sent on save either.
 *  * create mode redirects to the custom create page — a workflow with no
 *    version has no graph, and this form cannot author one.
 */
@Component({
  selector:   'attome-workflow-definition-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [OwnerLayerBadgeComponent, ReactiveFormsModule, RouterLink, DatePipe, TranslatePipe, XrmBaseFormComponent, XrmTabDirective],
  styleUrls:  ['../../../../../styles/xrm-form.css', './workflow-definition-form.component.css'],
  templateUrl: './workflow-definition-form.component.html',
})
export class WorkflowDefinitionFormComponent extends EngineFormBase {
  private readonly nav = inject(Router);
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly versions        = signal<VersionSummary[]>([]);
  readonly versionsLoading = signal(true);
  readonly versionError    = signal<string | null>(null);
  readonly creatingVersion = signal(false);
  readonly publishingId    = signal<string | null>(null);
  /** Solution 7 (D-785): the definition's owner layer, for the read-only badge. */
  readonly ownerLayer      = signal<string | null>(null);

  override ngOnInit(): void {
    if (!this.id()) {
      void this.nav.navigate(['/xrm/admin/workflow/definitions/new'], { replaceUrl: true });
      return;
    }
    super.ngOnInit();
    this.loadVersions();
  }

  /**
   * Versions come from the workflow engine's own admin API, not from the
   * entity record `EngineFormBase` loads — `workflow_definition_version` is
   * deliberately not a registered entity (see `attome_workflow::seed`'s header),
   * so there is no generic endpoint that would return them.
   */
  private loadVersions(): void {
    this.versionsLoading.set(true);
    this.api.get<DefinitionDetail>(`/api/v1/workflow/definitions/${this.id()}`).subscribe({
      next: d => {
        this.versions.set(d.versions);
        this.ownerLayer.set(d.owner_layer ?? null);
        this.versionsLoading.set(false);
      },
      error: (e: ApiError) => {
        this.versionError.set(e.message);
        this.versionsLoading.set(false);
      },
    });
  }

  createVersion(): void {
    this.creatingVersion.set(true);
    this.versionError.set(null);
    this.api.post(`/api/v1/workflow/definitions/${this.id()}/versions`, {}).subscribe({
      next:  () => { this.creatingVersion.set(false); this.loadVersions(); },
      error: (e: ApiError) => { this.versionError.set(e.message); this.creatingVersion.set(false); },
    });
  }

  publish(v: VersionSummary): void {
    this.publishingId.set(v.id);
    this.versionError.set(null);
    this.api.post(`/api/v1/workflow/definitions/${this.id()}/versions/${v.id}/publish`, {}).subscribe({
      next:  () => { this.publishingId.set(null); this.loadVersions(); },
      error: (e: ApiError) => { this.versionError.set(e.message); this.publishingId.set(null); },
    });
  }

  /** The definition's own fields and versions, then the platform record tabs
   * (D-773), which replace the stacked Communications and Notes sections. */
  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'general', label: 'General', icon: 'las la-list-alt' },
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }

  protected override buildFormGroup(schema: EntitySchema): FormGroup {
    const fg = super.buildFormGroup(schema);
    fg.get('logicalname')?.disable();
    return fg;
  }
}
