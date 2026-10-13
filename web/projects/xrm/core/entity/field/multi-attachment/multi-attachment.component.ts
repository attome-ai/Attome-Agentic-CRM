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
 * Multi-file attachment control — `AttachmentComponent`'s sibling for a
 * `file` field whose `options.multi` is `true` (`attome_field::FileOptions`,
 * D-362). The record column is JSONB holding an array of object keys instead
 * of one `TEXT` key, so this renders a list of attached rows plus a drop zone
 * that keeps accepting more, rather than the single-slot swap
 * `AttachmentComponent` renders.
 *
 * Same D-144 pipeline (create-session -> PUT -> finalize -> poll) as every
 * other file control, reused rather than re-implemented — the difference
 * here is entirely "run it once per queued file, sequentially" (bounded
 * concurrency: one presigned PUT and one scan poll in flight at a time, not
 * N concurrent ones for an N-file drop) and "append the resulting key to an
 * array instead of replacing a scalar".
 *
 *   <xrm-multi-attachment fieldName="attachments"
 *                         [entityName]="entityLogicalName"
 *                         [recordId]="id()" />
 *
 * Like every file field, controls only ever hold object keys — the record
 * itself is only updated when the surrounding form is saved.
 */
@Component({
  selector: 'xrm-multi-attachment',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  viewProviders: [{ provide: ControlContainer, useExisting: FormGroupDirective }],
  styleUrls: ['./multi-attachment.component.css'],
  templateUrl: './multi-attachment.component.html',
})
export class MultiAttachmentComponent implements OnInit, OnDestroy {
  /** Logical name of the multi-`file` field this control writes. */
  readonly fieldName  = input.required<string>();
  readonly entityName = input<string | null>(null);
  readonly recordId   = input<string | null>(null);

  readonly label       = input<string | null>(null);
  readonly required    = input(false);
  readonly placeholder = input('Drag documents or click to browse');
  readonly browseLabel = input('Browse');
  readonly hint        = input<string | null>(null);
  readonly gateHint    = input('Save the record before attaching files.');
  /** Caps how many attachments this field will hold at once. */
  readonly maxFiles    = input(20);

  readonly accept = input('');
  readonly maxSizeBytes = input(10 * 1024 * 1024);

  private readonly cc      = inject(ControlContainer);
  private readonly fileSvc = inject(FileUploadService);

  readonly state    = signal<'idle' | 'uploading' | 'processing' | 'rejected' | 'error'>('idle');
  readonly progress = signal(0);
  readonly message  = signal<string | null>(null);
  readonly dragging = signal(false);
  readonly downloadingKey = signal<string | null>(null);
  readonly uploadingName  = signal('');
  /** How many files are still waiting behind the one currently in flight. */
  readonly queueRemaining = signal(0);

  /**
   * Mirrors the host form's own control value as a signal — the native
   * `<input type="file">` carries no `formControlName`, so nothing else marks
   * this OnPush view for check when the control is patched from outside.
   * Reading this signal (rather than `this.ctrl.value` directly) from `keys`
   * — invoked from the template — is what lets a write here reschedule this
   * view's check without an explicit manual change-detection call.
   */
  private readonly ctrlValue = signal<unknown>(null);

  // Sequential by design (P-file-upload-pipeline's own rationale, extended to
  // "one field, many files"): one presigned PUT and one scan poll in flight
  // at a time, not an unbounded fan-out of concurrent uploads per drop.
  private readonly pipeline = new UploadPipeline(this.fileSvc);
  private queue: File[] = [];
  private ctrlSub?: Subscription;
  /** Keys the record already had at load time — what a download URL exists for. */
  private readonly persistedKeys = signal(new Set<string>());
  private sawInitialValue = false;

  get ctrl(): AbstractControl {
    return (this.cc.control as FormGroup).get(this.fieldName())!;
  }

  keys(): string[] {
    const v = this.ctrlValue();
    return Array.isArray(v) ? (v as string[]) : [];
  }

  busy(): boolean { return this.state() === 'uploading' || this.state() === 'processing'; }
  atCapacity(): boolean { return this.keys().length >= this.maxFiles(); }

  /** Same `{session_id}-{filename}` derivation as `AttachmentComponent.displayName`. */
  keyDisplayName(key: string): string {
    const last = key.split('/').pop() ?? key;
    return last.length > 37 ? last.slice(37) : last;
  }

  canDownload(key: string): boolean {
    return this.persistedKeys().has(key);
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
    this.onFilesSelected(event.dataTransfer?.files ?? null);
  }

  // ── Upload ────────────────────────────────────────────────────────────────
  onFilesSelected(files: FileList | null): void {
    const entityName = this.entityName();
    const recordId   = this.recordId();
    if (!files?.length || !entityName || !recordId) return;

    const accepted = this.accept().split(',').map(t => t.trim()).filter(Boolean);
    const room = Math.max(0, this.maxFiles() - this.keys().length - this.queue.length);
    let skipped = 0;
    const toQueue: File[] = [];

    for (const file of Array.from(files)) {
      if (toQueue.length >= room) { skipped++; continue; }
      if (file.type && accepted.length && !accepted.includes(file.type)) { skipped++; continue; }
      if (file.size > this.maxSizeBytes()) { skipped++; continue; }
      toQueue.push(file);
    }

    this.message.set(
      skipped > 0
        ? `${skipped} file(s) skipped (wrong type, too large, or over the ${this.maxFiles()}-file limit).`
        : null,
    );
    if (!toQueue.length) return;

    this.queue.push(...toQueue);
    if (!this.busy()) void this.processQueue();
  }

  private async processQueue(): Promise<void> {
    const entityName = this.entityName();
    const recordId   = this.recordId();
    if (!entityName || !recordId) return;

    while (this.queue.length) {
      const file = this.queue.shift()!;
      this.queueRemaining.set(this.queue.length);
      this.uploadingName.set(file.name);
      this.state.set('uploading');
      this.progress.set(0);

      const result = await this.pipeline.run(
        { entityName, recordId, fieldName: this.fieldName() },
        file,
        {
          onPhase:    phase   => { this.state.set(phase); },
          onProgress: percent => { this.progress.set(percent); },
        },
      );

      if (result.kind === 'clean') {
        this.ctrl.setValue([...this.keys(), result.finalKey]);
        this.ctrl.markAsDirty();
      } else {
        this.state.set(result.kind === 'rejected' ? 'rejected' : 'error');
        this.message.set(`${file.name}: ${result.message}`);
        // A rejected/errored file does not stop the rest of the queue — one
        // bad file in a batch drop should not silently drop its siblings.
      }
    }

    this.queue = [];
    this.queueRemaining.set(0);
    if (this.state() !== 'rejected' && this.state() !== 'error') this.state.set('idle');
  }

  download(key: string): void {
    const entityName = this.entityName();
    const recordId   = this.recordId();
    if (!entityName || !recordId) return;
    this.downloadingKey.set(key);
    this.fileSvc.getDownloadUrl(entityName, recordId, this.fieldName(), key).subscribe({
      next: res => {
        this.downloadingKey.set(null);
        window.open(res.download_url, '_blank', 'noopener');
      },
      error: () => { this.downloadingKey.set(null); },
    });
  }

  remove(key: string): void {
    this.ctrl.setValue(this.keys().filter(k => k !== key));
    this.ctrl.markAsDirty();
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────
  ngOnInit(): void {
    const initial = this.ctrl?.value;
    this.ctrlValue.set(initial);
    if (this.keys().length) {
      this.persistedKeys.set(new Set(this.keys()));
      this.sawInitialValue = true;
    }

    // Same reasoning as AttachmentComponent: the native file input carries no
    // formControlName, so nothing else marks this view for check when the
    // host form patches the control from outside (the record arriving after
    // this component rendered). Mirroring the value into `ctrlValue` is what
    // reschedules this OnPush view's check in place of a manual
    // change-detection call.
    this.ctrlSub = this.ctrl?.valueChanges.subscribe(value => {
      if (!this.sawInitialValue && Array.isArray(value) && value.length && this.state() === 'idle') {
        this.persistedKeys.set(new Set(value as string[]));
        this.sawInitialValue = true;
      }
      this.ctrlValue.set(value);
    });
  }

  ngOnDestroy(): void {
    this.pipeline.cancel();
    this.ctrlSub?.unsubscribe();
  }
}
