import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

import {
  ClientListItem, CreateClientBody, S2S_ENVIRONMENTS, S2sAdminService, S2sEnvironment,
} from '../services/s2s-admin.service';

/** The credential a new client was given, held only until it is dismissed. */
export interface IssuedCredential {
  clientDbId: string;
  clientId:   string;
  publicId:   string;
  secret:     string;
}

/**
 * The end of the chosen day, as the instant the API takes (`expires_at`).
 * `''` is no expiry.
 */
export function expiryInstant(day: string): string | undefined {
  return day ? new Date(`${day}T23:59:59Z`).toISOString() : undefined;
}

/**
 * S11-T6: the integration clients, with owner, purpose, how each signs in,
 * expiry and last use; and a new client, whose first key secret is shown
 * once with a copy button and never again.
 */
@Component({
  selector:   'attome-s2s-clients',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, RouterLink, LocalDatePipe, TranslatePipe],
  styleUrls:  ['../../styles/admin-page.css', './clients.component.css'],
  templateUrl: './clients.component.html',
})
export class S2sClientListComponent implements OnInit {
  private readonly svc    = inject(S2sAdminService);
  private readonly router = inject(Router);
  private readonly lang   = inject(LangService);

  readonly environments = S2S_ENVIRONMENTS;

  readonly clients      = signal<ClientListItem[]>([]);
  readonly loading      = signal(true);
  readonly error        = signal<string | null>(null);
  readonly showCreate   = signal(false);
  readonly creating     = signal(false);
  readonly createError  = signal<string | null>(null);
  readonly statusFilter = signal('');
  readonly search       = signal('');
  /** The new client's secret: shown until dismissed, never fetched again. */
  readonly issued       = signal<IssuedCredential | null>(null);
  readonly copied       = signal(false);

  newClientId    = '';
  newName        = '';
  newPurpose     = '';
  newEnvironment: S2sEnvironment | '' = '';
  newExpiry      = '';

  readonly filtered = computed(() => {
    const q = this.search().toLowerCase();
    return this.clients().filter(c =>
      q === ''
      || c.name.toLowerCase().includes(q)
      || c.client_id.includes(q)
      || (c.purpose ?? '').toLowerCase().includes(q)
      || (c.owner_email ?? '').toLowerCase().includes(q)
    );
  });

  ngOnInit(): void { this.load(); }

  setStatus(s: string): void { this.statusFilter.set(s); this.load(); }

  private load(): void {
    this.loading.set(true);
    this.svc.listClients(this.statusFilter() || undefined).subscribe({
      next:  cs => { this.clients.set(cs); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(this.lang.errorText(e)); this.loading.set(false); },
    });
  }

  toggleCreate(): void {
    this.showCreate.update(v => !v);
    this.newClientId = ''; this.newName = ''; this.newPurpose = '';
    this.newEnvironment = ''; this.newExpiry = '';
    this.createError.set(null);
  }

  /** Creates the client, then its primary key, whose secret is shown once. */
  create(): void {
    const client_id = this.newClientId.trim();
    const name      = this.newName.trim();
    if (!client_id || !name) {
      this.createError.set(this.lang.translate('s2sClients.required'));
      return;
    }
    const body: CreateClientBody = {
      client_id,
      name,
      purpose:     this.newPurpose.trim() || undefined,
      environment: this.newEnvironment || undefined,
      expires_at:  expiryInstant(this.newExpiry),
    };
    this.creating.set(true);
    this.createError.set(null);
    this.svc.createClient(body).subscribe({
      next: c => {
        this.svc.generateKey(c.id, { slot: 'primary' }).subscribe({
          next: key => {
            this.creating.set(false);
            this.showCreate.set(false);
            this.copied.set(false);
            this.issued.set({ clientDbId: c.id, clientId: c.client_id, publicId: key.public_id, secret: key.secret });
            this.load();
          },
          error: () => {
            // The client exists without a key; its page generates one.
            this.creating.set(false);
            this.router.navigate(['/xrm/admin/s2s/clients', c.id]);
          },
        });
      },
      error: (e: ApiError) => { this.creating.set(false); this.createError.set(this.lang.errorText(e)); },
    });
  }

  copySecret(): void {
    const issued = this.issued();
    if (!issued) return;
    navigator.clipboard?.writeText(issued.secret).then(
      () => this.copied.set(true),
      () => this.copied.set(false),
    );
  }

  /** Forgets the secret for good and opens the new client. */
  dismissSecret(): void {
    const issued = this.issued();
    this.issued.set(null);
    this.copied.set(false);
    if (issued) this.router.navigate(['/xrm/admin/s2s/clients', issued.clientDbId]);
  }
}
