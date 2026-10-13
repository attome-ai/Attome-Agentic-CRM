import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiError } from '@attome/base';

import { DataDomainItem, DataProtectionAdminService } from '../../../services/data-protection-admin.service';

/**
 * M15 (Data Governance, D-413) — the accountability register: named data
 * domains and the systemuser accountable for each (`steward_ref`, with an
 * optional `deputy_ref` backup). Creating a domain, naming its steward, and
 * assigning entities to it here is what makes
 * `/api/v1/admin/governance/domains/{id}/report` (this page's "Report" link)
 * answerable at all — before a domain exists and owns entities, the report
 * has nothing to show.
 */
@Component({
  selector: 'xrm-domain-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, DatePipe],
  styleUrls: ['../../../../../styles/admin-page.css', './domain-list.component.css'],
  templateUrl: './domain-list.component.html',
})
export class DomainListComponent implements OnInit {
  private readonly svc = inject(DataProtectionAdminService);
  private readonly router = inject(Router);

  readonly domains = signal<DataDomainItem[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  readonly showCreate = signal(false);
  readonly creating = signal(false);
  readonly createError = signal<string | null>(null);
  newName = '';
  newDescription = '';
  newStewardRef = '';
  newDeputyRef = '';

  /** The domain currently showing its inline "assign entities" form, or
   *  `null` when none is. Only one at a time, matching `legal-hold-list`'s
   *  single-panel-open convention. */
  readonly assigningId = signal<string | null>(null);
  readonly assigning = signal(false);
  readonly assignError = signal<string | null>(null);
  assignEntitiesInput = '';

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.svc.listDomains().subscribe({
      next: page => {
        this.domains.set(page.items);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.loading.set(false);
      },
    });
  }

  toggleCreate(): void {
    this.showCreate.update(v => !v);
    this.newName = '';
    this.newDescription = '';
    this.newStewardRef = '';
    this.newDeputyRef = '';
    this.createError.set(null);
  }

  create(): void {
    const name = this.newName.trim();
    if (!name) {
      this.createError.set('Name is required.');
      return;
    }
    this.creating.set(true);
    this.createError.set(null);
    this.svc
      .createDomain({
        name,
        description: this.newDescription.trim() || undefined,
        steward_ref: this.newStewardRef.trim() || undefined,
        deputy_ref: this.newDeputyRef.trim() || undefined,
      })
      .subscribe({
        next: () => {
          this.creating.set(false);
          this.showCreate.set(false);
          this.load();
        },
        error: (e: ApiError) => {
          this.creating.set(false);
          this.createError.set(e.message);
        },
      });
  }

  startAssign(d: DataDomainItem): void {
    this.assigningId.set(d.id);
    this.assignEntitiesInput = '';
    this.assignError.set(null);
  }

  cancelAssign(): void {
    this.assigningId.set(null);
  }

  submitAssign(d: DataDomainItem): void {
    const names = this.assignEntitiesInput
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    if (names.length === 0) {
      this.assignError.set('Enter at least one entity logicalname, comma-separated.');
      return;
    }
    this.assigning.set(true);
    this.assignError.set(null);
    this.svc.assignEntities(d.id, names).subscribe({
      next: () => {
        this.assigning.set(false);
        this.assigningId.set(null);
      },
      error: (e: ApiError) => {
        this.assigning.set(false);
        this.assignError.set(e.message);
      },
    });
  }

  viewReport(d: DataDomainItem): void {
    void this.router.navigate(['/xrm/admin/data-protection/domains', d.id]);
  }
}
