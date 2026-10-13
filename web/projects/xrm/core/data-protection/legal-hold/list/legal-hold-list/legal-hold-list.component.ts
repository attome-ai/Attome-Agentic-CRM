import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiError } from '@attome/base';

import { DataProtectionAdminService, LegalHoldItem } from '../../../services/data-protection-admin.service';

/**
 * P-data-protection-governance §4 (D-266) — the admin surface that actually
 * places/releases a `legal_hold` row (`legal_hold_admin.rs`).
 * Without this page, `attome_core::legal_hold::record_is_held` (checked
 * by purge/erasure/DSR-erasure) has no way to ever return `Some` outside a
 * direct database write. `record_id` empty = a whole-entity hold.
 */
@Component({
  selector:   'xrm-legal-hold-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, DatePipe],
  styleUrls:  ['../../../../../styles/admin-page.css', './legal-hold-list.component.css'],
  templateUrl: './legal-hold-list.component.html',
})
export class LegalHoldListComponent implements OnInit {
  private readonly svc = inject(DataProtectionAdminService);

  readonly holds        = signal<LegalHoldItem[]>([]);
  readonly loading      = signal(true);
  readonly error        = signal<string | null>(null);
  readonly showCreate   = signal(false);
  readonly creating     = signal(false);
  readonly createError  = signal<string | null>(null);
  readonly statusFilter = signal<'active' | 'released'>('active');
  readonly busyId       = signal<string | null>(null);

  entityFilter      = '';
  newEntity          = '';
  newRecordId        = '';
  newMatterReference = '';

  ngOnInit(): void { this.load(); }

  setStatus(s: 'active' | 'released'): void { this.statusFilter.set(s); this.load(); }

  load(): void {
    this.loading.set(true);
    this.svc.listLegalHolds(this.statusFilter(), this.entityFilter.trim() || undefined).subscribe({
      next:  page => { this.holds.set(page.items); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  toggleCreate(): void {
    this.showCreate.update(v => !v);
    this.newEntity = ''; this.newRecordId = ''; this.newMatterReference = '';
    this.createError.set(null);
  }

  create(): void {
    const entity_logicalname = this.newEntity.trim();
    const matter_reference    = this.newMatterReference.trim();
    if (!entity_logicalname || !matter_reference) {
      this.createError.set('Entity logicalname and matter reference are both required.');
      return;
    }
    this.creating.set(true);
    this.createError.set(null);
    this.svc.placeLegalHold({
      entity_logicalname,
      matter_reference,
      record_id: this.newRecordId.trim() || undefined,
    }).subscribe({
      next:  () => { this.creating.set(false); this.showCreate.set(false); this.load(); },
      error: (e: ApiError) => { this.creating.set(false); this.createError.set(e.message); },
    });
  }

  release(h: LegalHoldItem): void {
    this.busyId.set(h.id);
    this.svc.releaseLegalHold(h.id).subscribe({
      next:  () => { this.busyId.set(null); this.load(); },
      error: (e: ApiError) => { this.busyId.set(null); this.error.set(e.message); },
    });
  }
}
