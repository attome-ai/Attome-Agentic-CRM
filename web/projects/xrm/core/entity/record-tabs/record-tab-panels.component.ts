import { ChangeDetectionStrategy, Component, computed, effect, input, signal } from '@angular/core';
import { NgComponentOutlet } from '@angular/common';
import { TranslatePipe } from '@attome/base';
import type { XrmFormTabDef } from '../base/xrm-form.base';
import { ActivitiesPanelComponent } from '../activities/activities-panel.component';
import { CommunicationsPanelComponent } from '../communications/communications-panel.component';
import { ConsentPanelComponent } from '../consent/consent-panel.component';
import { DocumentFolderBrowserComponent } from '../document-folder/document-folder-browser.component';
import { NotesPanelComponent } from '../notes/notes-panel.component';
import { RelationshipExplorerComponent } from '../relationship-explorer/relationship-explorer.component';
import { TagsPanelComponent } from '../tags/tags-panel.component';

/**
 * The tab panels for the record tabs `recordTabDefs` declares. Drop it inside
 * a form's `.xf-body`, after the form's own panels, passing the form's whole
 * `tabs()` list: it renders a panel for each record tab present in that list
 * and nothing for the form's own tabs, so the tab strip and the panels can
 * never disagree about which record tabs exist.
 *
 * `idPrefix` must match the prefix the form's tab buttons use for their
 * `id`/`aria-controls` (`'entity'` for the generic form, giving
 * `entity-tab-notes` / `entity-panel-notes`).
 *
 * The timeline and history panels (U3/U6, D-601) live in their own entry
 * point, `@attome/xrm/core/entity/record-activity`, loaded with a dynamic
 * `import()` the first time either tab is opened: this component's chunk is
 * shared by every entity form and sits at the lazy-chunk budget. Each panel is
 * created only while its tab is active (and destroyed when it is left), so
 * opening a form costs neither request, and returning to the tab shows fresh
 * data after an edit.
 *
 * The host is `display: contents`, so each panel lays out as a direct child
 * of `.xf-body` exactly as it did when the panels were inline in
 * `EntityFormComponent`'s template.
 */
type RecordActivityModule = typeof import('@attome/xrm/core/entity/record-activity');

@Component({
  selector: 'xrm-record-tab-panels',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    TranslatePipe, ActivitiesPanelComponent, CommunicationsPanelComponent, ConsentPanelComponent,
    DocumentFolderBrowserComponent, NgComponentOutlet, NotesPanelComponent, RelationshipExplorerComponent,
    TagsPanelComponent,
  ],
  // Only the two rules the panels need (see the css file) — not all of
  // xrm-form.css, whose ~17 kB would otherwise be copied into the
  // core/entity chunk a second time and push it over the lazy-chunk budget.
  styleUrls: ['./record-tab-panels.component.css'],
  templateUrl: './record-tab-panels.component.html',
})
export class RecordTabPanelsComponent {
  readonly entityName = input.required<string>();
  readonly recordId   = input<string | null>(null);
  readonly tabs       = input.required<XrmFormTabDef[]>();
  readonly activeTab  = input.required<string>();
  readonly idPrefix   = input('entity');

  private readonly present = computed(() => new Set(this.tabs().map(t => t.id)));

  /** The record-activity entry point, once a Timeline/History tab has asked for it. */
  readonly activity = signal<RecordActivityModule | null>(null);
  readonly activityLoadFailed = signal(false);
  private activityRequested = false;

  /** Inputs for whichever record-activity panel is showing. */
  readonly activityInputs = computed(() => ({ entityName: this.entityName(), recordId: this.recordId() }));

  constructor() {
    effect(() => {
      const tab = this.activeTab();
      if ((tab === 'timeline' || tab === 'history') && this.recordId() && !this.activityRequested) {
        this.activityRequested = true;
        import('@attome/xrm/core/entity/record-activity').then(
          m => this.activity.set(m),
          () => this.activityLoadFailed.set(true),
        );
      }
    });
  }

  has(tab: string): boolean {
    return this.present().has(tab);
  }

  panelId(tab: string): string {
    return `${this.idPrefix()}-panel-${tab}`;
  }

  tabId(tab: string): string {
    return `${this.idPrefix()}-tab-${tab}`;
  }
}
