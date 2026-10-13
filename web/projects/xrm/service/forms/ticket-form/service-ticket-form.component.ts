import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { EntityRecordResponse, RecordTabId, XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';
import { SlaBadgeComponent } from '../../sla/sla-badge/sla-badge.component';
import { TicketSlaActionsComponent } from '../../sla/ticket-sla-actions/ticket-sla-actions.component';

/** The shared record tabs a ticket carries (U14), with U2's Activities and U3/U6's Timeline and History. */
export const TICKET_RECORD_TABS: readonly RecordTabId[] = [
  'documents', 'communications', 'notes', 'activities', 'relationships', 'timeline', 'history',
];

/**
 * Hand-coded form for `service_ticket`, scaffolded from platform-bundles/attome-service.json's
 * "synthesized (no authored layout)" layout by scripts/bundle-to-form-component.mjs. Same
 * field-rendering approach as the generic dispatcher (<attome-field-input> per
 * schema field), but its own component/template — edit freely; re-running
 * the generator only overwrites this file with --force.
 *
 * Tab/section/field grouping below mirrors the bundle's layout at
 * generation time. The bundle JSON remains the source of truth for the
 * entity/fields themselves (schema, validation, choices) — only the form's
 * *presentation* moved to hand-written code.
 *
 * U14: besides Details it carries the shared record tabs (`recordTabDefs` +
 * `<xrm-record-tab-panels>`, the same ones the generic form renders), an SLA
 * badge in the header and the SLA actions bar. The badge reads
 * `ticketData`, the server's copy of the record, not the form's values: the
 * SLA columns are server-computed, and a badge that followed unsaved edits
 * would claim a status the ticket does not have.
 */
@Component({
  selector:   'attome-service-ticket-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    ReactiveFormsModule, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent,
    SlaBadgeComponent, TicketSlaActionsComponent,
  ],
  styleUrls:  ['../../../styles/xrm-form.css', './service-ticket-form.component.css'],
  templateUrl: './service-ticket-form.component.html',
})
export class ServiceTicketFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  /** The last record the server returned — see the class comment. */
  readonly ticketData = signal<Record<string, unknown> | null>(null);

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'details', label: 'Details', icon: 'las la-list-alt' },
      ...recordTabDefs(this.name(), key => this.lang.translate(key), TICKET_RECORD_TABS),
    ];
  }

  protected override onRecordLoaded(record: EntityRecordResponse): void {
    this.ticketData.set(record.data as Record<string, unknown>);
  }

  /** Looks up loaded schema fields by logicalname, in this form's fixed layout order. */
  protected fieldsIn(names: string[]): FieldSchema[] {
    const all = this.schema()?.fields ?? [];
    return names.map(n => all.find(f => f.name === n)).filter((f): f is FieldSchema => !!f);
  }
}
