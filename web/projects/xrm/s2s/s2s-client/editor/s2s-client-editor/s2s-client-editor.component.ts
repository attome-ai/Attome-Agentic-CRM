import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';

import {
  AccessLogItem, ClientDetail, PermissionItem, S2S_ENVIRONMENTS, S2sAdminService, S2sEnvironment,
  SetPermissionBody, TrustItem,
} from '../../../services/s2s-admin.service';
import { expiryInstant } from '../../../clients/clients.component';

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
  imports:    [FormsModule, RouterLink, DatePipe, TranslatePipe],
  styleUrls:  ['../../../../styles/admin-page.css', './s2s-client-editor.component.css'],
  templateUrl: './s2s-client-editor.component.html',
})
export class S2sClientEditorComponent implements OnInit {
  private readonly svc = inject(S2sAdminService);
  private readonly lang = inject(LangService);

  readonly id = input.required<string>();
  readonly slots = SLOTS;
  readonly environments = S2S_ENVIRONMENTS;

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
  readonly copied        = signal(false);
  /** S11-T2: the client's identity-provider trusts. */
  readonly trusts        = signal<TrustItem[]>([]);
  readonly showTrustForm = signal(false);
  readonly savingTrust   = signal(false);
  readonly trustError    = signal<string | null>(null);
  /** S11-T6: the empty key slot a rotation fills, if any. */
  readonly freeSlot = computed(() => SLOTS.find(s => !this.client()?.keys.some(k => k.slot === s && k.status === 'active')) ?? null);
  /** Both slots hold an active key: the old one is to be retired. */
  readonly bothActive = computed(() => this.freeSlot() === null);

  /** S11-T4: the service-account fields. */
  editPurpose = '';
  editEnvironment: S2sEnvironment | '' = '';
  /** The expiry day (`YYYY-MM-DD`), as the date input holds it. */
  editExpiry = '';
  private loadedExpiry = '';
  trustIssuer = '';
  trustAudience = '';
  trustSubject = '';
  trustJwksUri = '';

  editName        = '';
  editDescription = '';
  editStatus      = 'active';
  editRpm         = '';
  editMaxConcurrent = '';
  /** S1-T11: the grant to act as a named user. */
  editCanActAs = false;
  /** S11-T1: a new public key to store (blank keeps the current one). */
  editOauthKey = '';
  /** A PEM header, not interface text, so it is not in the catalogue. */
  readonly pemPlaceholder = '-----BEGIN PUBLIC KEY-----';
  /** S11-T1: whether to remove the stored key on save. */
  removeOauthKey = false;
  /** S11-T1: the OAuth scopes, space-separated. */
  editOauthScopes = '';
  permForm: PermForm = emptyPermForm();

  ngOnInit(): void { this.load(); this.loadLogs(); this.loadTrusts(); }

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
        this.editCanActAs = c.can_act_as_user;
        this.editOauthKey = '';
        this.removeOauthKey = false;
        this.editOauthScopes = (c.oauth_scopes ?? []).join(' ');
        this.editPurpose = c.purpose ?? '';
        this.editEnvironment = c.environment ?? '';
        this.editExpiry = c.expires_at ? c.expires_at.slice(0, 10) : '';
        this.loadedExpiry = this.editExpiry;
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
      can_act_as_user: this.editCanActAs,
      oauth_public_key_pem: this.removeOauthKey ? '' : (this.editOauthKey.trim() || undefined),
      oauth_scopes:   this.editOauthScopes.split(/\s+/).filter(s => s.length > 0),
      purpose:        this.editPurpose.trim() || undefined,
      environment:    this.editEnvironment || undefined,
      // Only a changed day is sent: the API takes a future expiry.
      expires_at:     this.editExpiry !== this.loadedExpiry ? expiryInstant(this.editExpiry) : undefined,
      row_version:    c.row_version,
    }).subscribe({
      next:  updated => {
        this.client.set(updated);
        this.editOauthKey = '';
        this.removeOauthKey = false;
        this.savingMeta.set(false);
      },
      error: (e: ApiError) => { this.metaError.set(e.message); this.savingMeta.set(false); },
    });
  }

  generateKey(slot: string): void {
    this.generating.set(true);
    this.keyError.set(null);
    this.svc.generateKey(this.id(), { slot }).subscribe({
      next: created => {
        this.copied.set(false);
        this.revealedSecret.set(created.secret);
        this.generating.set(false);
        this.load();
      },
      error: (e: ApiError) => { this.keyError.set(e.message); this.generating.set(false); },
    });
  }

  /** S11-T6: a second credential in the empty slot; both then work until the old one is retired. */
  rotate(): void {
    const slot = this.freeSlot();
    if (slot) this.generateKey(slot);
  }

  copySecret(): void {
    const secret = this.revealedSecret();
    if (!secret) return;
    navigator.clipboard?.writeText(secret).then(
      () => this.copied.set(true),
      () => this.copied.set(false),
    );
  }

  /** Forgets the secret for good. */
  dismissSecret(): void {
    this.revealedSecret.set(null);
    this.copied.set(false);
  }

  private loadTrusts(): void {
    this.svc.listTrusts(this.id()).subscribe({
      next:  ts => this.trusts.set(ts),
      error: () => this.trusts.set([]),
    });
  }

  addTrust(): void {
    const body = {
      issuer: this.trustIssuer.trim(), audience: this.trustAudience.trim(),
      subject: this.trustSubject.trim(), jwks_uri: this.trustJwksUri.trim(),
    };
    if (!body.issuer || !body.audience || !body.subject || !body.jwks_uri) {
      this.trustError.set(this.lang.translate('s2sClients.trustRequired'));
      return;
    }
    this.savingTrust.set(true);
    this.trustError.set(null);
    this.svc.createTrust(this.id(), body).subscribe({
      next: () => {
        this.savingTrust.set(false);
        this.showTrustForm.set(false);
        this.trustIssuer = ''; this.trustAudience = ''; this.trustSubject = ''; this.trustJwksUri = '';
        this.loadTrusts();
      },
      error: (e: ApiError) => { this.savingTrust.set(false); this.trustError.set(this.lang.errorText(e)); },
    });
  }

  removeTrust(trustId: string): void {
    this.svc.deleteTrust(this.id(), trustId).subscribe({
      next:  () => this.loadTrusts(),
      error: (e: ApiError) => this.trustError.set(this.lang.errorText(e)),
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
