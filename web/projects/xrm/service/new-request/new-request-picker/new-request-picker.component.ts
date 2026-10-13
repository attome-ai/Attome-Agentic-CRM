import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, AuthService } from '@attome/base';

import { OfferingSummary, ServiceAdminService, CreateWorkRequestFromOfferingResponse } from '../../services/service-admin.service';

/**
 * The "New Request" picker — an authenticated user browses the active
 * `service_offering` catalog and files a work request against one,
 * inheriting that offering's priority/SLA/queue defaults
 * (`attome_service::offering::create_work_request_from_offering`). The offering
 * catalog itself (create/edit an offering) is admin work and renders through
 * the generic metadata-driven list/form pages at `/xrm/service/offering/…`,
 * the same way `service_work_request`/`service_ticket` already do (D-398) — this
 * component only covers the "start a request from the catalog" flow.
 */
@Component({
  selector: 'attome-service-new-request-picker',
  standalone: true,
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['../../../styles/admin-page.css', './new-request-picker.component.css'],
  templateUrl: './new-request-picker.component.html',
})
export class NewRequestPickerComponent implements OnInit {
  private readonly svc = inject(ServiceAdminService);
  private readonly auth = inject(AuthService);

  readonly offerings = signal<OfferingSummary[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  readonly selectedOfferingId = signal<string | null>(null);
  readonly title = signal('');
  readonly description = signal('');
  readonly requestType = signal('it_request');
  readonly requestTypes = [
    'project_request', 'change_request', 'issue_report',
    'it_request', 'hr_request', 'access_request', 'custom',
  ];

  readonly submitting = signal(false);
  readonly submitError = signal<string | null>(null);
  readonly result = signal<CreateWorkRequestFromOfferingResponse | null>(null);

  ngOnInit(): void {
    this.svc.listActiveOfferings().subscribe({
      next: offerings => {
        this.offerings.set(offerings);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.loading.set(false);
      },
    });
  }

  select(offering: OfferingSummary): void {
    this.selectedOfferingId.set(offering.id);
  }

  submit(): void {
    const offeringId = this.selectedOfferingId();
    const requesterId = this.auth.userId();
    const title = this.title().trim();
    if (!offeringId || !requesterId || !title) return;

    this.submitting.set(true);
    this.submitError.set(null);
    this.svc.createWorkRequestFromOffering(offeringId, {
      title,
      description: this.description().trim() || null,
      request_type: this.requestType(),
      requester_id: requesterId,
    }).subscribe({
      next: response => {
        this.result.set(response);
        this.submitting.set(false);
      },
      error: (e: ApiError) => {
        this.submitError.set(e.message);
        this.submitting.set(false);
      },
    });
  }

  startAnother(): void {
    this.result.set(null);
    this.selectedOfferingId.set(null);
    this.title.set('');
    this.description.set('');
  }
}
