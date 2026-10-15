import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal } from '@angular/core';
import { LangService, LiveChannel, LiveRecords, TranslatePipe } from '@attome/base';
import { EntityService } from '../services/entity.service';

/** What the banner says happened to the open record. */
export interface ServerChange {
  deleted: boolean;
  /** Who last changed it, when the record names them. */
  by: string | null;
  /** When it last changed (ISO 8601), when known. */
  at: string | null;
}

/**
 * A16-T4: tells the person editing a record that it changed on the server
 * since the form loaded it. Watches the record's entity on the live channel;
 * when a change names this record (or the channel could not list them all),
 * re-reads the record and shows the banner if its `row_version` is no longer
 * the one the form holds. The form's own save updates `rowVersion`, so it
 * never warns about itself. Stops watching when the form closes or moves to
 * another record.
 */
@Component({
  selector: 'xrm-record-changed-banner',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (change(); as c) {
      <div class="xf-warning-banner" role="status" data-record-changed>
        <i class="las la-sync" aria-hidden="true"></i>
        <span>
          @if (c.deleted) {
            {{ 'xrmForm.recordDeleted' | translate }}
          } @else if (c.by) {
            {{ 'xrmForm.recordChangedBy' | translate: { name: c.by, time: time() } }}
          } @else {
            {{ 'xrmForm.recordChanged' | translate: { time: time() } }}
          }
        </span>
        @if (!c.deleted) {
          <button type="button" class="xf-btn xf-btn-secondary" data-record-changed-reload (click)="reload.emit()">
            {{ 'xrmForm.recordChangedReload' | translate }}
          </button>
        }
      </div>
    }
  `,
})
export class RecordChangedBannerComponent {
  private readonly live = inject(LiveChannel);
  private readonly svc = inject(EntityService);
  private readonly lang = inject(LangService);

  readonly entity = input.required<string>();
  readonly recordId = input<string | null>(null);
  /** The `row_version` the form loaded or last saved. */
  readonly rowVersion = input<number | null>(null);
  /** The person asked to load the server's version. */
  readonly reload = output<void>();

  readonly change = signal<ServerChange | null>(null);

  readonly time = computed(() => {
    const at = this.change()?.at;
    if (!at) return '';
    const date = new Date(at);
    return Number.isNaN(date.getTime())
      ? ''
      : new Intl.DateTimeFormat(this.lang.intlLocale(), { timeStyle: 'short' }).format(date);
  });

  constructor() {
    effect(onCleanup => {
      const entity = this.entity();
      const id = this.recordId();
      this.change.set(null);
      if (!id) return;
      const unwatch = this.live.watch(entity);
      const sub = this.live.records.subscribe(frame => this.onFrame(frame, entity, id));
      onCleanup(() => {
        sub.unsubscribe();
        unwatch();
      });
    });
    // A reload or save that brings the form level with the server clears it.
    effect(() => {
      this.rowVersion();
      this.change.set(null);
    });
  }

  /** Applies one live `records` frame for the record `entity`/`id`. */
  onFrame(frame: LiveRecords, entity: string, id: string): void {
    if ('overflow' in frame) {
      this.check(entity, id);
      return;
    }
    const mine = frame.changes.filter(c => c.entity === entity && c.id === id);
    if (!mine.length) return;
    if (mine.some(c => c.op === 'delete')) {
      this.change.set({ deleted: true, by: null, at: null });
      return;
    }
    this.check(entity, id);
  }

  private check(entity: string, id: string): void {
    this.svc.get(entity, id).subscribe({
      next: record => {
        if (this.recordId() !== id || record.row_version === this.rowVersion()) return;
        this.change.set({
          deleted: false,
          by: record.lookups?.['modified_by']?.name ?? null,
          at: record.updated_at ?? null,
        });
      },
      // Unreadable now (deleted, or access withdrawn): say it is gone.
      error: () => {
        if (this.recordId() === id) this.change.set({ deleted: true, by: null, at: null });
      },
    });
  }
}
