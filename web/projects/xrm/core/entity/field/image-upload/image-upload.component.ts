import {
  ChangeDetectionStrategy, Component, OnDestroy, OnInit, inject, input, signal,
} from '@angular/core';
import {
  AbstractControl, ControlContainer, FormGroup, FormGroupDirective,
} from '@angular/forms';
import { Subscription } from 'rxjs';
import { TranslatePipe } from '@attome/base';

import { FileUploadService } from '../file-upload.service';
import { UploadPipeline } from '../upload-pipeline';

/**
 * Avatar/image picker for a `file`-typed entity field — drag-and-drop, a round
 * live preview, upload progress, and the malware-scan wait, all against the
 * same pipeline the generic file field uses (upload-pipeline.ts, D-144).
 *
 * Reads and writes the host form's control directly (`ControlContainer`, the
 * pattern `field-input.component.ts` already uses), so a host template only
 * needs the control name:
 *
 *   <xrm-image-upload fieldName="profile_image"
 *                     [entityName]="entityLogicalName"
 *                     [recordId]="id()" />
 *
 * Like every other file field, the control ends up holding the promoted
 * object key — the record itself is only updated when the surrounding form is
 * saved.
 *
 * Shape: a dashed square, a circle inside it, the glyph inside that, and no
 * copy at rest — what to do lives in the tooltip, and words only appear when
 * there is something to report. `.xf-grid-photo` gives the cell a two-field-row
 * height and a column of the same width, so the card is square; the host's
 * `flex: 1` and `--xiu-min-height` floor keep it that size anywhere else. A
 * chosen image fills the whole card, and every transient state (progress, scan
 * wait, errors) reuses the same one line, so the card never changes height.
 */
@Component({
  selector: 'xrm-image-upload',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  viewProviders: [{ provide: ControlContainer, useExisting: FormGroupDirective }],
  styleUrls: ['./image-upload.component.css'],
  templateUrl: './image-upload.component.html',
})
export class ImageUploadComponent implements OnInit, OnDestroy {
  /** Logicalname of the `file` field this picker writes — the form control key. */
  readonly fieldName  = input.required<string>();
  /** Both required before an upload session can exist (the routes are record-scoped). */
  readonly entityName = input<string | null>(null);
  readonly recordId   = input<string | null>(null);

  readonly label   = input('Profile image');
  /** Lead line of the tooltip — the card itself stays wordless at rest. */
  readonly hint    = input('Drag & drop or click to browse');
  /** Client-side guard; the server enforces `storage.max_upload_size_bytes` too. */
  readonly maxSizeBytes = input(5 * 1024 * 1024);

  // The server's own allowlist (files.rs::ALLOWED_CONTENT_TYPES) is wider than
  // this — it also covers PDFs and office documents. An avatar field narrows it
  // to the image subset, which is a UX guard, never the security boundary: the
  // scan job re-derives the real content type from the uploaded bytes.
  private static readonly IMAGE_TYPES = [
    'image/png', 'image/jpeg', 'image/gif', 'image/webp',
  ];
  readonly acceptAttr = ImageUploadComponent.IMAGE_TYPES.join(',');

  private readonly cc      = inject(ControlContainer);
  private readonly fileSvc = inject(FileUploadService);

  readonly state      = signal<'idle' | 'uploading' | 'processing' | 'rejected' | 'error'>('idle');
  readonly progress   = signal(0);
  readonly message    = signal<string | null>(null);
  readonly dragging   = signal(false);
  readonly previewUrl = signal<string | null>(null);

  /**
   * Mirrors the host form's own control value as a signal — the native
   * `<input type="file">` carries no `formControlName`, so nothing else marks
   * this OnPush view for check when the control is patched from outside.
   * Reading this signal (rather than `this.ctrl.value` directly) from
   * `hasValue`/`pendingSave` — both invoked from the template — is what lets
   * a write here reschedule this view's check without an explicit manual
   * change-detection call.
   */
  private readonly ctrlValue = signal<unknown>(null);

  private readonly pipeline = new UploadPipeline(this.fileSvc);
  private ctrlSub?: Subscription;
  /** The value the record already had at load time — what a download URL exists for. */
  private readonly persistedValue = signal<string | null>(null);
  /** Revoked before being replaced; a leaked blob URL pins the file in memory. */
  private objectUrl: string | null = null;

  get ctrl(): AbstractControl {
    return (this.cc.control as FormGroup).get(this.fieldName())!;
  }

  busy(): boolean { return this.state() === 'uploading' || this.state() === 'processing'; }

  hasValue(): boolean { return !!this.ctrlValue(); }

  /** A value that differs from what was loaded is uploaded but not yet saved. */
  pendingSave(): boolean {
    const v = this.ctrlValue() ?? null;
    return !!v && v !== this.persistedValue();
  }

  /**
   * The constraints, on hover. The card itself is two lines by design, so the
   * accepted formats and the size ceiling have nowhere to live in it — an
   * offending file reports itself inline instead.
   */
  tooltip(): string {
    return `${this.hint()} — PNG, JPEG, GIF, or WebP, up to ${this.formatSize(this.maxSizeBytes())}.`;
  }

  /**
   * Whether the prompt layer must stay visible over an existing photo: hover
   * is fine for "click to change", but progress, a scan wait, a failure, or an
   * unsaved upload are things the user has to see without pointing at them.
   */
  pinned(): boolean {
    return this.busy() || this.failed() || this.pendingSave();
  }

  /** A rejection or an upload error — the two states that show a long message. */
  failed(): boolean {
    return this.state() === 'rejected' || this.state() === 'error';
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

    if (!ImageUploadComponent.IMAGE_TYPES.includes(file.type)) {
      this.state.set('error');
      this.message.set('That file is not an image. Choose a PNG, JPEG, GIF, or WebP.');
      return;
    }
    if (file.size > this.maxSizeBytes()) {
      this.state.set('error');
      this.message.set(`That image is too large (limit ${this.formatSize(this.maxSizeBytes())}).`);
      return;
    }

    // Shown immediately, so the crop/framing is visible while the bytes are
    // still moving — replaced by nothing on success (the promoted object isn't
    // downloadable until the record is saved) and cleared on failure.
    this.setPreviewFromFile(file);
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
      this.revokeObjectUrl();
      this.previewUrl.set(null);
      this.loadPersistedPreview();
      this.state.set(result.kind === 'rejected' ? 'rejected' : 'error');
      this.message.set(result.message);
    }
  }

  clear(): void {
    this.ctrl.setValue(null);
    this.ctrl.markAsDirty();
    this.revokeObjectUrl();
    this.previewUrl.set(null);
    this.state.set('idle');
    this.message.set(null);
  }

  private formatSize(bytes: number): string {
    const mb = bytes / (1024 * 1024);
    return mb >= 1 ? `${Math.round(mb)} MB` : `${Math.round(bytes / 1024)} KB`;
  }

  // ── Preview plumbing ──────────────────────────────────────────────────────
  private setPreviewFromFile(file: File): void {
    this.revokeObjectUrl();
    this.objectUrl = URL.createObjectURL(file);
    this.previewUrl.set(this.objectUrl);
  }

  private revokeObjectUrl(): void {
    if (this.objectUrl) {
      URL.revokeObjectURL(this.objectUrl);
      this.objectUrl = null;
    }
  }

  /**
   * `download-url` reads the *persisted* column, so it is only asked for when
   * the control still holds the value the record was loaded with — a
   * just-uploaded key would 422 there until the form is saved.
   */
  private loadPersistedPreview(): void {
    const entityName = this.entityName();
    const recordId   = this.recordId();
    const persisted  = this.persistedValue();
    if (!entityName || !recordId || !persisted) return;
    if (this.ctrl?.value !== persisted) return;

    this.fileSvc.getDownloadUrl(entityName, recordId, this.fieldName()).subscribe({
      next: res => { this.previewUrl.set(res.download_url); },
      // A missing/expired object is not an error worth shouting about — the
      // fallback initials stand in for it.
      error: () => { this.previewUrl.set(null); },
    });
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────
  ngOnInit(): void {
    const initial = (this.ctrl?.value as string | null) ?? null;
    this.persistedValue.set(initial);
    this.ctrlValue.set(initial);
    this.loadPersistedPreview();

    // The native <input type="file"> carries no formControlName (browsers won't
    // let one be pre-filled), so nothing else marks this view for check when
    // the host form patches the control from outside — e.g. the record arriving
    // after this component rendered. Mirroring the value into `ctrlValue` is
    // what reschedules this OnPush view's check in place of a manual
    // change-detection call. Same reason field-input.component.ts subscribes
    // on its own file control.
    this.ctrlSub = this.ctrl?.valueChanges.subscribe(value => {
      if (this.persistedValue() === null && typeof value === 'string' && value && this.state() === 'idle') {
        // First value seen outside an upload = the loaded record's own image.
        this.persistedValue.set(value);
        this.loadPersistedPreview();
      }
      this.ctrlValue.set(value);
    });
  }

  ngOnDestroy(): void {
    this.pipeline.cancel();
    this.ctrlSub?.unsubscribe();
    this.revokeObjectUrl();
  }
}
