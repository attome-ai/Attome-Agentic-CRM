import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError } from '@attome/base';

import {
  AccessLogItem, ClientDetail, PermissionItem, S2sAdminService, SetPermissionBody,
} from '../../../services/s2s-admin.service';

const SLOTS = ['primary', 'secondary'] as const;

interface PermForm {
  entity_name: string;
  can_read:    boolean;
  can_create:  boolean;
  can_update:  boolean;
  can_delete:  boolean;
  can_export:  boolean;
  can_bulk:    boolean;
}

function emptyPermForm(): PermForm {
  return { entity_name: '', can_read: true, can_create: false, can_update: false, can_delete: false, can_export: false, can_bulk: false };
}

@Component({
  selector:   'attome-s2s-client-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, RouterLink, DatePipe],
  styleUrls:  ['../../../../styles/admin-page.css', './s2s-client-editor.component.css'],
  templateUrl: './s2s-client-editor.component.html',
})
export class S2sClientEditorComponent implements OnInit {
  private readonly svc = inject(S2sAdminService);

  readonly id = input.required<string>();
  readonly slots = SLOTS;

  readonly client        = signal<ClientDetail | null>(null);
  readonly loading       = signal(true);
  readonly error         = signal<string | null>(null);
  readonly savingMeta    = signal(false);
  readonly metaError     = signal<string | null>(null);
  readonly generating    = signal(false);
  readonly keyError      = signal<string | null>(null);
  readonly revealedSecret = signal<string | null>(null);
  readonly showPermForm  = signal(false);
  readonly savingPerm    = signal(false);
  readonly permError     = signal<string | null>(null);
  readonly logs          = signal<AccessLogItem[]>([]);
  readonly logTotal      = signal(0);
  readonly logsLoading   = signal(true);

  editName        = '';
  editDescription = '';
  editStatus      = 'active';
  editRpm         = '';
  editMaxConcurrent = '';
  permForm: PermForm = emptyPermForm();

  ngOnInit(): void { this.load(); this.loadLogs(); }

  keyFor(slot: string) { return this.client()?.keys.find(k => k.slot === slot) ?? null; }

  private load(): void {
    this.loading.set(true);
    this.svc.getClient(this.id()).subscribe({
      next: c => {
        this.client.set(c);
        this.editName = c.name;
        this.editDescription = c.description ?? '';
        this.editStatus = c.status;
        this.editRpm = String(c.rate_limit_rpm);
        this.editMaxConcurrent = String(c.max_concurrent);
        this.loading.set(false);
      },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  private loadLogs(): void {
    this.logsLoading.set(true);
    this.svc.listLogs(this.id()).subscribe({
      next:  page => { this.logs.set(page.items); this.logTotal.set(page.total); this.logsLoading.set(false); },
      error: () => { this.logsLoading.set(false); },
    });
  }

  saveMeta(): void {
    const c = this.client();
    if (!c) return;
    this.savingMeta.set(true);
    this.metaError.set(null);
    this.svc.updateClient(this.id(), {
      name:           this.editName,
      description:    this.editDescription || undefined,
      status:         this.editStatus,
      rate_limit_rpm: Number(this.editRpm),
      max_concurrent: Number(this.editMaxConcurrent),
      row_version:    c.row_version,
    }).subscribe({
      next:  updated => { this.client.set(updated); this.savingMeta.set(false); },
      error: (e: ApiError) => { this.metaError.set(e.message); this.savingMeta.set(false); },
    });
  }

  generateKey(slot: string): void {
    this.generating.set(true);
    this.keyError.set(null);
    this.svc.generateKey(this.id(), { slot }).subscribe({
      next: created => {
        this.revealedSecret.set(created.secret);
        this.generating.set(false);
        this.load();
      },
      error: (e: ApiError) => { this.keyError.set(e.message); this.generating.set(false); },
    });
  }

  revokeKey(slot: string): void {
    if (!confirm(`Revoke the ${slot} key? This cannot be undone.`)) return;
    this.svc.revokeKey(this.id(), slot).subscribe({
      next:  () => this.load(),
      error: (e: ApiError) => { this.keyError.set(e.message); },
    });
  }

  savePermission(): void {
    const entity_name = this.permForm.entity_name.trim();
    if (!entity_name) { this.permError.set('Entity logical name is required.'); return; }
    const body: SetPermissionBody = { ...this.permForm, entity_name };
    this.savingPerm.set(true);
    this.permError.set(null);
    this.svc.setPermission(this.id(), body).subscribe({
      next: () => {
        this.savingPerm.set(false);
        this.showPermForm.set(false);
        this.permForm = emptyPermForm();
        this.load();
      },
      error: (e: ApiError) => { this.permError.set(e.message); this.savingPerm.set(false); },
    });
  }

  removePermission(p: PermissionItem): void {
    if (!confirm(`Remove the permission for "${p.entity_name}"?`)) return;
    this.svc.deletePermission(this.id(), p.entity_name).subscribe({
      next:  () => this.load(),
      error: (e: ApiError) => alert(e.message),
    });
  }
}
