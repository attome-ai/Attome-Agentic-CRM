import {
  ChangeDetectionStrategy, Component, DestroyRef, ElementRef, inject, input, output, signal, viewChild,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';

import { FileUploadService, FileVersion, RestoreVersionResponse } from '../file-upload.service';
import { RecordChangeNotifier } from '../../services/record-change-notifier.service';

let nextPanelId = 0;

/**
 * U18 (M55 P2) — the "Versions" disclosure on a single-file field: every
 * version the server recorded for the field, newest first, each downloadable
 * (`download-url?version=N`), restorable (non-current only) and purgeable
 * (non-current only, behind a confirm; the server still refuses one under
 * legal hold or retention with a 409, shown as the panel's error).
 *
 * Authorization is entirely the server's (record Read for the list, Update for
 * restore/purge): a 403 lands in the panel's error line, nothing is hidden on
 * a guess.
 *
 * A restore rewrites the record's field and bumps its `row_version`, so this
 * emits `restored` (the host widget shows the restored key) and tells the
 * hosting form through `RecordChangeNotifier` to re-read the record — without
 * that the form's next save would 409.
 */
@Component({
  selector: 'xrm-file-versions',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  styleUrls: ['./file-versions.component.css'],
  templateUrl: './file-versions.component.html',
})
export class FileVersionsComponent {
  readonly entityName = input.required<string>();
  readonly recordId   = input.required<string>();
  readonly fieldName  = input.required<string>();

  readonly restored = output<RestoreVersionResponse>();

  private readonly fileSvc    = inject(FileUploadService);
  private readonly dialog     = inject(DialogService);
  private readonly lang       = inject(LangService);
  private readonly notifier   = inject(RecordChangeNotifier);
  private readonly destroyRef = inject(DestroyRef);

  private readonly trigger = viewChild<ElementRef<HTMLButtonElement>>('trigger');

  readonly panelId  = `xrm-file-versions-${++nextPanelId}`;
  readonly open     = signal(false);
  readonly loading  = signal(false);
  readonly versions = signal<FileVersion[]>([]);
  readonly error    = signal<string | null>(null);
  readonly status   = signal<string | null>(null);
  /** `version_no` of the row whose action is in flight, or `null`. */
  readonly busyVersion = signal<number | null>(null);

  toggle(): void {
    if (this.open()) { this.close(); return; }
    this.open.set(true);
    this.load();
  }

  close(): void {
    this.open.set(false);
    this.trigger()?.nativeElement.focus();
  }

  onPanelKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape') { event.stopPropagation(); this.close(); }
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.fileSvc.listVersions(this.entityName(), this.recordId(), this.fieldName())
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: page => { this.versions.set(page.items); this.loading.set(false); },
        error: (e: ApiError) => { this.loading.set(false); this.error.set(e.message); },
      });
  }

  /** `{session_id}-{filename}` → `filename` (files.rs::final_key). */
  fileName(version: FileVersion): string {
    const last = version.object_key.split('/').pop() ?? version.object_key;
    return last.length > 37 ? last.slice(37) : last;
  }

  formatSize(bytes: number | null | undefined): string {
    if (bytes === null || bytes === undefined) return '';
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  }

  download(version: FileVersion): void {
    this.busyVersion.set(version.version_no);
    this.error.set(null);
    this.fileSvc.getDownloadUrl(this.entityName(), this.recordId(), this.fieldName(), { version: version.version_no })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: res => {
          this.busyVersion.set(null);
          window.open(res.download_url, '_blank', 'noopener');
        },
        error: (e: ApiError) => { this.busyVersion.set(null); this.error.set(e.message); },
      });
  }

  restore(version: FileVersion): void {
    if (version.is_current) return;
    this.busyVersion.set(version.version_no);
    this.error.set(null);
    this.status.set(null);
    const entityName = this.entityName();
    const recordId = this.recordId();
    const fieldName = this.fieldName();
    this.fileSvc.restoreVersion(entityName, recordId, fieldName, version.version_no)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: res => {
          this.busyVersion.set(null);
          this.status.set(this.lang.translate('fileVersions.restored', { version: res.version_no }));
          this.restored.emit(res);
          this.notifier.notify({ entityName, recordId, fields: [fieldName] });
          this.load();
        },
        error: (e: ApiError) => { this.busyVersion.set(null); this.error.set(e.message); },
      });
  }

  async purge(version: FileVersion): Promise<void> {
    if (version.is_current) return;
    const confirmed = await this.dialog.confirm({
      title:       this.lang.translate('fileVersions.purgeTitle'),
      message:     this.lang.translate('fileVersions.purgeConfirm', { version: version.version_no }),
      confirmText: this.lang.translate('fileVersions.purge'),
      cancelText:  this.lang.translate('fileVersions.cancel'),
      variant:     'danger',
    });
    if (!confirmed) return;
    this.busyVersion.set(version.version_no);
    this.error.set(null);
    this.status.set(null);
    this.fileSvc.purgeVersion(this.entityName(), this.recordId(), this.fieldName(), version.version_no)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.busyVersion.set(null);
          this.status.set(this.lang.translate('fileVersions.purged', { version: version.version_no }));
          this.versions.update(list => list.filter(v => v.version_no !== version.version_no));
        },
        error: (e: ApiError) => { this.busyVersion.set(null); this.error.set(e.message); },
      });
  }
}
