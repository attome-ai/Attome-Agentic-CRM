import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ApiError } from '@attome/base';

import { ClientListItem, CreateClientBody, S2sAdminService } from '../../../services/s2s-admin.service';

@Component({
  selector:   'attome-s2s-client-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, RouterLink, DatePipe],
  styleUrls:  ['../../../../styles/admin-page.css', './s2s-client-list.component.css'],
  templateUrl: './s2s-client-list.component.html',
})
export class S2sClientListComponent implements OnInit {
  private readonly svc    = inject(S2sAdminService);
  private readonly router = inject(Router);

  readonly clients      = signal<ClientListItem[]>([]);
  readonly loading      = signal(true);
  readonly error        = signal<string | null>(null);
  readonly showCreate   = signal(false);
  readonly creating     = signal(false);
  readonly createError  = signal<string | null>(null);
  readonly statusFilter = signal('');

  search          = '';
  newClientId     = '';
  newName         = '';
  newRpm          = '';
  newMaxConcurrent = '';

  readonly filtered = computed(() => {
    const q = this.search.toLowerCase();
    return this.clients().filter(c =>
      q === '' || c.name.toLowerCase().includes(q) || c.client_id.includes(q)
    );
  });

  ngOnInit(): void { this.load(); }

  setStatus(s: string): void { this.statusFilter.set(s); this.load(); }

  private load(): void {
    this.loading.set(true);
    this.svc.listClients(this.statusFilter() || undefined).subscribe({
      next:  cs => { this.clients.set(cs); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  toggleCreate(): void {
    this.showCreate.update(v => !v);
    this.newClientId = ''; this.newName = ''; this.newRpm = ''; this.newMaxConcurrent = '';
    this.createError.set(null);
  }

  create(): void {
    const client_id = this.newClientId.trim();
    const name      = this.newName.trim();
    if (!client_id || !name) {
      this.createError.set('Both client ID and name are required.');
      return;
    }
    const body: CreateClientBody = {
      client_id,
      name,
      rate_limit_rpm: this.newRpm ? Number(this.newRpm) : undefined,
      max_concurrent: this.newMaxConcurrent ? Number(this.newMaxConcurrent) : undefined,
    };
    this.creating.set(true);
    this.createError.set(null);
    this.svc.createClient(body).subscribe({
      next:  c => { this.creating.set(false); this.showCreate.set(false); this.router.navigate(['/xrm/admin/s2s/clients', c.id]); },
      error: (e: ApiError) => { this.creating.set(false); this.createError.set(e.message); },
    });
  }
}
