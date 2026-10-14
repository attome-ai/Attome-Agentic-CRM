import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

/** `license_admin::UsageResponse`. */
export interface Usage {
  modules_on: string[];
  users_active: number;
  users_signed_in_30d: number;
  contract_reference: string | null;
}

/**
 * Usage (roadmap U11-T1): the modules this deployment runs, how many people
 * can sign in and have signed in lately, and the contract reference. There
 * are no seats or expiry dates (D-778): information, not enforcement.
 * Logical CSS only.
 */
@Component({
  selector:        'xrm-usage',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [TranslatePipe],
  templateUrl:     './usage.component.html',
  styleUrls:       ['./usage.component.css'],
})
export class UsageComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly usage = signal<Usage | null>(null);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.api.get<Usage>('/api/v1/admin/usage').subscribe({
      next: u => this.usage.set(u),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
