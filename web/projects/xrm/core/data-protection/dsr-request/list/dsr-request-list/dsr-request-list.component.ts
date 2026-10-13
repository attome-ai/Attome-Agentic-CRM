import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError } from '@attome/base';

import {
  DataProtectionAdminService,
  DsrRequestItem,
  DsrScope,
  FulfillErasureResult,
  FulfillExportResult,
} from '../../../services/data-protection-admin.service';

/**
 * P-data-protection-governance §4/§6 (D-266/D-269) — the DSR (data-subject-
 * rights) admin surface: track requests and fulfill access/portability/
 * erasure against `dsr_admin.rs`. A pending request's row expands into a
 * scope builder (which entities + which attribute identifies the subject in
 * each — `dsr_admin.rs` validates `match_attribute` against the entity's
 * live registered attributes, this UI does not duplicate that check
 * client-side) and the one fulfillment action matching its own
 * `request_type` (access/portability/erasure are mutually exclusive per
 * request — the backend 409s a mismatched endpoint, so only the matching
 * button is ever shown). Erasure fulfillment may come back either executed
 * immediately or `approval_pending: true` (D-269's D-195 four-eyes gate,
 * deployment-opt-in via `approval.required_actions`) — the pending case
 * links to the Approval Queue rather than pretending the action already ran.
 */
@Component({
  selector:   'xrm-dsr-request-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, DatePipe, RouterLink],
  styleUrls:  ['../../../../../styles/admin-page.css', './dsr-request-list.component.css'],
  templateUrl: './dsr-request-list.component.html',
})
export class DsrRequestListComponent implements OnInit {
  private readonly svc = inject(DataProtectionAdminService);

  readonly requests      = signal<DsrRequestItem[]>([]);
  readonly loading       = signal(true);
  readonly error         = signal<string | null>(null);
  readonly showCreate    = signal(false);
  readonly creating      = signal(false);
  readonly createError   = signal<string | null>(null);
  readonly statusFilter  = signal('');

  readonly expandedId           = signal<string | null>(null);
  readonly scopes                = signal<DsrScope[]>([{ entity_logicalname: '', match_attribute: '' }]);
  readonly fulfilling            = signal(false);
  readonly fulfillError          = signal<string | null>(null);
  readonly fulfillPendingMessage = signal<string | null>(null);
  readonly exportResult          = signal<FulfillExportResult | null>(null);
  readonly erasureResult         = signal<FulfillErasureResult | null>(null);
  adminOverride = false;

  newSubjectReference = '';
  newRequestType       = 'access';

  ngOnInit(): void { this.load(); }

  setStatus(s: string): void { this.statusFilter.set(s); this.load(); }

  private load(): void {
    this.loading.set(true);
    this.svc.listDsrRequests(this.statusFilter() || undefined).subscribe({
      next:  page => { this.requests.set(page.items); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  toggleCreate(): void {
    this.showCreate.update(v => !v);
    this.newSubjectReference = ''; this.newRequestType = 'access';
    this.createError.set(null);
  }

  create(): void {
    const subject_reference = this.newSubjectReference.trim();
    if (!subject_reference) {
      this.createError.set('Subject reference is required.');
      return;
    }
    this.creating.set(true);
    this.createError.set(null);
    this.svc.createDsrRequest({ subject_reference, request_type: this.newRequestType }).subscribe({
      next:  () => { this.creating.set(false); this.showCreate.set(false); this.load(); },
      error: (e: ApiError) => { this.creating.set(false); this.createError.set(e.message); },
    });
  }

  toggleFulfill(r: DsrRequestItem): void {
    if (this.expandedId() === r.id) {
      this.expandedId.set(null);
      return;
    }
    this.expandedId.set(r.id);
    this.scopes.set([{ entity_logicalname: '', match_attribute: '' }]);
    this.adminOverride = false;
    this.fulfillError.set(null);
    this.fulfillPendingMessage.set(null);
    this.exportResult.set(null);
    this.erasureResult.set(null);
  }

  addScope(): void {
    this.scopes.update(s => [...s, { entity_logicalname: '', match_attribute: '' }]);
  }

  removeScope(i: number): void {
    this.scopes.update(s => s.filter((_, idx) => idx !== i));
  }

  private validScopes(): DsrScope[] | null {
    const scopes = this.scopes()
      .map(s => ({ entity_logicalname: s.entity_logicalname.trim(), match_attribute: s.match_attribute.trim() }))
      .filter(s => s.entity_logicalname && s.match_attribute);
    if (scopes.length === 0) {
      this.fulfillError.set('At least one scope (entity + match attribute) is required.');
      return null;
    }
    return scopes;
  }

  fulfillAccess(r: DsrRequestItem): void {
    const scopes = this.validScopes();
    if (!scopes) return;
    this.fulfilling.set(true);
    this.fulfillError.set(null);
    this.svc.fulfillAccess(r.id, { scopes, admin_override: this.adminOverride }).subscribe({
      next:  res => { this.fulfilling.set(false); this.exportResult.set(res); this.load(); },
      error: (e: ApiError) => { this.fulfilling.set(false); this.fulfillError.set(e.message); },
    });
  }

  fulfillPortability(r: DsrRequestItem): void {
    const scopes = this.validScopes();
    if (!scopes) return;
    this.fulfilling.set(true);
    this.fulfillError.set(null);
    this.svc.fulfillPortability(r.id, { scopes, admin_override: this.adminOverride }).subscribe({
      next:  res => { this.fulfilling.set(false); this.exportResult.set(res); this.load(); },
      error: (e: ApiError) => { this.fulfilling.set(false); this.fulfillError.set(e.message); },
    });
  }

  fulfillErasure(r: DsrRequestItem): void {
    const scopes = this.validScopes();
    if (!scopes) return;
    this.fulfilling.set(true);
    this.fulfillError.set(null);
    this.fulfillPendingMessage.set(null);
    this.svc.fulfillErasure(r.id, { scopes }).subscribe({
      next: res => {
        this.fulfilling.set(false);
        if ('approval_pending' in res) {
          this.fulfillPendingMessage.set(`Submitted for four-eyes approval (request ${res.approval_request_id})`);
        } else {
          this.erasureResult.set(res);
          this.load();
        }
      },
      error: (e: ApiError) => { this.fulfilling.set(false); this.fulfillError.set(e.message); },
    });
  }
}
