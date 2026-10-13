import {
  ChangeDetectionStrategy, Component, OnDestroy, OnInit, inject, input, signal,
} from '@angular/core';
import {
  AbstractControl, ControlContainer, FormGroup, FormGroupDirective,
} from '@angular/forms';
import { Subscription } from 'rxjs';
import { TranslatePipe } from '@attome/base';

import { FileUploadService, RestoreVersionResponse } from '../file-upload.service';
import { UploadPipeline } from '../upload-pipeline';
import { FileVersionsComponent } from '../file-versions/file-versions.component';

/**
 * Generic single-file attachment control — a compact one-row drop zone that
 * collapses into a progress bar while the bytes move and into a named file row
 * once the object is clean.
 *
 * The third consumer of the D-144 upload pipeline, after `field-input`'s plain
 * file row and `image-upload`'s avatar picker: same create-session -> PUT ->
 * finalize -> poll sequence (upload-pipeline.ts owns it), different shell. Use
 * this one wherever a document is being collected against a named slot — a
 * passport scan, a signed contract, a compliance certificate — and the form
 * wants one dense row rather than a card.
 *
 * Reads and writes the host form's control directly (`ControlContainer`, the
 * same pattern `field-input.component.ts` and `image-upload.component.ts`
 * use), so a host template only needs the control name:
 *
 *   <xrm-attachment fieldName="passport_scan"
 *                   label="Passport scan"
 *                   [entityName]="entityLogicalName"
 *                   [recordId]="id()" />
 *
 * Like every other file field, the control ends up holding the promoted object
 * key — the record itself is only updated when the surrounding form is saved.
 */
@Component({
  selector: 'xrm-attachment',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FileVersionsComponent, TranslatePipe],
  viewProviders: [{ provide: ControlContainer, useExisting: FormGroupDirective }],
  styleUrls: ['./attachment.component.css'],
  templateUrl: './attachment.component.html',
})
export class AttachmentComponent implements OnInit, OnDestroy {
  /** Logical name of the `file` field this control writes — the form control key. */
  readonly fieldName  = input.required<string>();
  /** Both required before an upload session can exist (the routes are record-scoped). */
  readonly entityName = input<string | null>(null);
  readonly recordId   = input<string | null>(null);

  /** Optional caption above the row; omit it when the host already renders one. */
  readonly label       = input<string | null>(null);
  readonly required    = input(false);
  readonly placeholder = input('Drag document or click to browse');
  readonly browseLabel = input('Browse');
  /** Sub-line under the row, shown only while there is no status message. */
  readonly hint        = input<string | null>(null);
  readonly gateHint    = input('Save the record before attaching a file.');

  /**
   * `accept` attribute and the client-side type guard. Defaults to the server's
   * own allowlist (`files.rs::ALLOWED_CONTENT_TYPES`); narrow it per slot when
   * a field only makes sense as, say, a PDF. Either way this is a UX guard and
   * never the security boundary — the scan job re-derives the real content type
   * from the uploaded bytes.
   */
  readonly accept = input(
    [
      'application/pdf',
      'image/png', 'image/jpeg', 'image/gif', 'image/webp',
      'text/plain', 'text/csv',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ].join(','),
  );
  /** Client-side guard; the server enforces `storage.max_upload_size_bytes` too. */
  readonly maxSizeBytes = input(10 * 1024 * 1024);

  private readonly cc      = inject(ControlContainer);
  private readonly fileSvc = inject(FileUploadService);

  readonly state    = signal<'idle' | 'uploading' | 'processing' | 'rejected' | 'error'>('idle');
  readonly progress = signal(0);
  readonly message  = signal<string | null>(null);
  readonly dragging = signal(false);
  readonly downloading = signal(false);
  /** Name of the file currently in flight — the row shows it, the key doesn't exist yet. */
  readonly uploadingName = signal('');

  /**
   * Mirrors the host form's own control value as a signal — the native
   * `<input type="file">` carries no `formControlName`, so nothing else marks
   * this OnPush view for check when the control is patched from outside (the
   * record arriving after this component rendered, or `setValue` from
   * `onFileSelected`/`clear` below). Reading this signal (rather than
   * `this.ctrl.value` directly) from `hasValue`/`displayName`/`canDownload` —
   * all invoked from the template — is what lets a write here reschedule this
   * view's check without an explicit manual change-detection call.
   */
  private readonly ctrlValue = signal<unknown>(null);

  private readonly pipeline = new UploadPipeline(this.fileSvc);
  private ctrlSub?: Subscription;
  /** The value the record already had at load time — what a download URL exists for. */
  private readonly persistedValue = signal<string | null>(null);

  get ctrl(): AbstractControl {
    return (this.cc.control as FormGroup).get(this.fieldName())!;
  }

  busy(): boolean { return this.state() === 'uploading' || this.state() === 'processing'; }

  hasValue(): boolean { return !!this.ctrlValue(); }

  /**
   * final_key's shape is `{session_id}-{filename}` (files.rs::final_key) —
   * session_id is always a 36-char UUID, so the filename starts at index 37.
   * Same derivation as `field-input.component.ts::fileDisplayName`.
   */
  displayName(): string {
    const key = this.ctrlValue();
    if (typeof key !== 'string' || !key) return '';
    const last = key.split('/').pop() ?? key;
    return last.length > 37 ? last.slice(37) : last;
  }

  /**
   * A locally-set value (just uploaded, not yet saved on the record) can't be
   * downloaded yet — `download-url` reads the *persisted* column, not the
   * form's pending value.
   */
  canDownload(): boolean {
    const v = this.ctrlValue();
    return !!v && v === this.persistedValue();
  }

  // ── Drag and drop ─────────────────────────────────────────────────────────
  onDragOver(event: DragEvent): void {
    event.preventDefault();
    if (!this.busy()) this.dragging.set(true);
  }

  onDragLeave(event: DragEvent): void {
    event.preventDefault();
    this.dragging.set(false);
  }

  onDrop(event: DragEvent): void {
    event.preventDefault();
    this.dragging.set(false);
    if (this.busy()) return;
    void this.onFileSelected(event.dataTransfer?.files ?? null);
  }

  // ── Upload ────────────────────────────────────────────────────────────────
  async onFileSelected(files: FileList | null): Promise<void> {
    const file = files?.[0];
    const entityName = this.entityName();
    const recordId   = this.recordId();
    if (!file || !entityName || !recordId) return;

    const accepted = this.accept().split(',').map(t => t.trim()).filter(Boolean);
    if (file.type && accepted.length && !accepted.includes(file.type)) {
      this.state.set('error');
      this.message.set('That file type is not accepted for this attachment.');
      return;
    }
    if (file.size > this.maxSizeBytes()) {
      this.state.set('error');
      this.message.set(`That file is too large (limit ${this.formatSize(this.maxSizeBytes())}).`);
      return;
    }

    this.uploadingName.set(file.name);
    this.state.set('uploading');
    this.progress.set(0);
    this.message.set(null);

    const result = await this.pipeline.run(
      { entityName, recordId, fieldName: this.fieldName() },
      file,
      {
        onPhase:    phase   => { this.state.set(phase); },
        onProgress: percent => { this.progress.set(percent); },
      },
    );

    if (result.kind === 'clean') {
      this.ctrl.setValue(result.finalKey);
      this.ctrl.markAsDirty();
      this.state.set('idle');
      this.message.set(null);
    } else {
      this.state.set(result.kind === 'rejected' ? 'rejected' : 'error');
      this.message.set(result.message);
    }
  }

  download(): void {
    const entityName = this.entityName();
    const recordId   = this.recordId();
    if (!entityName || !recordId) return;
    this.downloading.set(true);
    this.fileSvc.getDownloadUrl(entityName, recordId, this.fieldName()).subscribe({
      next: res => {
        this.downloading.set(false);
        window.open(res.download_url, '_blank', 'noopener');
      },
      error: () => { this.downloading.set(false); },
    });
  }

  /** U18 — a prior version was made current on the server (which also wrote
   * the record's field), so it is the persisted, downloadable value now. The
   * versions panel has already told the hosting form to re-read the record. */
  onVersionRestored(res: RestoreVersionResponse): void {
    this.persistedValue.set(res.object_key);
    this.ctrl.setValue(res.object_key);
    this.state.set('idle');
    this.message.set(null);
  }

  clear(): void {
    this.ctrl.setValue(null);
    this.ctrl.markAsDirty();
    this.state.set('idle');
    this.message.set(null);
    this.uploadingName.set('');
  }

  private formatSize(bytes: number): string {
    const mb = bytes / (1024 * 1024);
    return mb >= 1 ? `${Math.round(mb)} MB` : `${Math.round(bytes / 1024)} KB`;
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────
  ngOnInit(): void {
    const initial = (this.ctrl?.value as string | null) ?? null;
    this.persistedValue.set(initial);
    this.ctrlValue.set(initial);

    // The native <input type="file"> carries no formControlName (browsers won't
    // let one be pre-filled), so nothing else marks this view for check when
    // the host form patches the control from outside — e.g. the record arriving
    // after this component rendered. Mirroring the value into `ctrlValue`
    // (read from the template via `hasValue`/`displayName`/`canDownload`) is
    // what reschedules this OnPush view's check, in place of a manual
    // change-detection call. Same reason field-input.component.ts and
    // image-upload.component.ts subscribe on their own file controls.
    this.ctrlSub = this.ctrl?.valueChanges.subscribe(value => {
      if (this.persistedValue() === null && typeof value === 'string' && value && this.state() === 'idle') {
        // First value seen outside an upload = the loaded record's own file.
        this.persistedValue.set(value);
      }
      this.ctrlValue.set(value);
    });
  }

  ngOnDestroy(): void {
    this.pipeline.cancel();
    this.ctrlSub?.unsubscribe();
  }
}
