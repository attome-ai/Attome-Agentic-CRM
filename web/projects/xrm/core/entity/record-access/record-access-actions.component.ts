import { ChangeDetectionStrategy, Component, inject, input, output, signal } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';
// Deferred: the dialog's chunk loads the first time Assign or Share is
// clicked (`@defer` in the template), so this always-rendered button pair is
// all the record form and the list carry until an admin uses it.
import { RecordAccessDialogComponent } from './record-access-dialog.component';
import type { RecordAccessMode } from './record-access';

/** The privilege the shell's own admin gate reads (`AccessService.hasPrivilege`
 * short-circuits on `is_admin`). */
const ADMIN_PRIVILEGE = 'system.admin';

/**
 * U7 Phase A — "Assign" and "Share" for one record (the form header) or
 * "Assign" for a selection (the list's bulk actions), over the existing admin
 * record-share routes.
 *
 * Renders nothing unless the signed-in user is an admin. That is presentation
 * only: every route it calls is `Authorized<Admin>` server-side, so a
 * non-admin who reached the dialog anyway would get a 403. B-R11 (Phase B)
 * is what adds `{entity}.assign`/`{entity}.share` privileges; until then
 * these buttons stay admin-only.
 */
@Component({
  selector: 'xrm-record-access-actions',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, RecordAccessDialogComponent],
  templateUrl: './record-access-actions.component.html',
  styleUrl: './record-access-actions.component.css',
})
export class RecordAccessActionsComponent {
  private readonly access = inject(AccessService);

  /** Logical name of the records' entity. */
  readonly entity     = input.required<string>();
  /** The record (form) or the selection (list). */
  readonly recordIds  = input.required<readonly string[]>();
  /** Share is per record — the list's bulk bar offers Assign only. */
  readonly allowShare = input(true);
  readonly disabled   = input(false);
  /** Look of the buttons: the form header's `xf-btn` or the list's `btn`. */
  readonly variant    = input<'form' | 'list'>('list');

  /** An owner was reassigned or a share changed — the host refreshes. */
  readonly changed = output<void>();

  readonly mode = signal<RecordAccessMode | null>(null);
  /** Latches on the first click; renders the deferred dialog. */
  readonly requested = signal(false);

  constructor() {
    // The shell's privilege bootstrap: one shared `whoami` per page load.
    this.access.ready().subscribe();
  }

  isAdmin(): boolean { return this.access.hasPrivilege(ADMIN_PRIVILEGE); }

  open(mode: RecordAccessMode): void {
    if (this.disabled() || !this.recordIds().length) return;
    this.requested.set(true);
    this.mode.set(mode);
  }

  onClosed(changed: boolean): void {
    this.mode.set(null);
    if (changed) this.changed.emit();
  }
}
