import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

/** `license_admin::UsageResponse`. */
export interface Usage {
  modules_on: string[];
  users_active: number;
  users_signed_in_30d: number;
  contract_reference: string | null;
}

/** `settings_admin::BackupStatus`. */
export interface BackupStatus {
  enabled: boolean;
  runs_here: boolean;
  files: boolean;
  dir: string;
  keep: number;
  hour: number;
  same_disk: boolean;
  archives: number;
  latest: { name: string; taken_at: string | null; size_bytes: number; files: number | null } | null;
}

/** A backup older than this is reported as late. */
export const BACKUP_LATE_HOURS = 36;

/**
 * Usage (roadmap U11-T1): the modules this deployment runs, how many people
 * can sign in and have signed in lately, and the contract reference. There
 * are no seats or expiry dates (D-778): information, not enforcement. Also
 * the daily backup (U6-T1): where it goes, the newest one, and a warning
 * when it shares the database's disk or is late. Logical CSS only.
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
  readonly backup = signal<BackupStatus | null>(null);

  /** True when the newest backup is older than {@link BACKUP_LATE_HOURS}, or there is none. */
  backupLate(b: BackupStatus, now = Date.now()): boolean {
    const taken = b.latest?.taken_at ? Date.parse(b.latest.taken_at) : NaN;
    return !Number.isFinite(taken) || now - taken > BACKUP_LATE_HOURS * 3_600_000;
  }

  ngOnInit(): void {
    this.api.get<BackupStatus>('/api/v1/admin/backup').subscribe({
      next: b => this.backup.set(b),
      error: () => this.backup.set(null),
    });
    this.api.get<Usage>('/api/v1/admin/usage').subscribe({
      next: u => this.usage.set(u),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
