import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError } from '@attome/base';

import { PublicOffering, PortalStatus, ServicePortalService } from '../services/service-portal.service';

/**
 * The self-service portal (M70 target design §3, D-423) — the host app's
 * public route for browsing published service offerings and checking a
 * previously-issued request's status by token. No session, no privileges:
 * both sections call the anonymous bypass routes
 * (`GET /api/v1/service-portal/offerings`, `GET /api/v1/service-portal/status`).
 *
 * There is no public "submit a request" flow here — only the two checklist
 * items this crate actually ships (browse + status-by-token). Filing a
 * request against a public offering today still goes through the
 * authenticated "New Request" picker (`@attome/xrm/service`); wiring an
 * anonymous submission path is real, separate follow-up work.
 */
@Component({
  selector: 'attome-service-portal-page',
  standalone: true,
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./portal-page.component.css'],
  templateUrl: './portal-page.component.html',
})
export class PortalPageComponent implements OnInit {
  private readonly svc = inject(ServicePortalService);

  readonly offerings = signal<PublicOffering[]>([]);
  readonly offeringsLoading = signal(true);
  readonly offeringsError = signal<string | null>(null);

  readonly tokenInput = signal('');
  readonly statusLoading = signal(false);
  readonly statusError = signal<string | null>(null);
  readonly status = signal<PortalStatus | null>(null);
  /** Distinguishes "never looked anything up" from "looked up, found nothing". */
  readonly hasSearched = signal(false);

  ngOnInit(): void {
    this.svc.listPublicOfferings().subscribe({
      next: offerings => {
        this.offerings.set(offerings);
        this.offeringsLoading.set(false);
      },
      error: (e: ApiError) => {
        this.offeringsError.set(e.message);
        this.offeringsLoading.set(false);
      },
    });
  }

  checkStatus(): void {
    const token = this.tokenInput().trim();
    if (!token) return;

    this.statusLoading.set(true);
    this.statusError.set(null);
    this.status.set(null);
    this.svc.lookupStatus(token).subscribe({
      next: status => {
        this.status.set(status);
        this.hasSearched.set(true);
        this.statusLoading.set(false);
      },
      // A 404 (unknown/malformed/wrong token) is not an application error
      // here — it's "nothing found for that token", the same status the
      // portal shows for any other miss, never a distinguishable message.
      error: () => {
        this.status.set(null);
        this.hasSearched.set(true);
        this.statusLoading.set(false);
      },
    });
  }
}
