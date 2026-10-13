import { HttpEventType } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import type { ApiError } from '@attome/base';

import { FileUploadService } from './file-upload.service';

/**
 * The client half of P-file-upload-pipeline (D-144): create session -> PUT to
 * the presigned quarantine URL -> finalize -> poll until the async scan job
 * (`files_scan.rs`) promotes the object to `clean` and hands back its
 * `final_key`.
 *
 * Extracted from `field-input.component.ts` when a second consumer appeared
 * (`image-upload.component.ts`): the two render completely different UI —
 * a file row versus an avatar drop zone — but the sequence between them is
 * security-sensitive and must stay identical, so it lives in one place rather
 * than being copied. UI state stays in the components; this class only reports
 * phase/progress through `UploadHandlers`.
 */

export interface UploadTarget {
  entityName: string;
  recordId:   string;
  fieldName:  string;
}

export interface UploadHandlers {
  /** 'uploading' while bytes move, 'processing' once the scan job owns it. */
  onPhase?(phase: 'uploading' | 'processing'): void;
  /** 0–100, only during the 'uploading' phase. */
  onProgress?(percent: number): void;
}

export type UploadResult =
  | { kind: 'clean';    finalKey: string }
  | { kind: 'rejected'; message: string }
  | { kind: 'error';    message: string };

const POLL_INTERVAL_MS = 1500;
// ~60s total — bounds files_scan.rs's own 30s CLAMD_TIMEOUT plus queue pickup
// latency; past this the scan is still running server-side, just not worth
// making the user watch a spinner for.
const POLL_MAX_ATTEMPTS = 40;

export class UploadPipeline {
  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private cancelled = false;

  constructor(private readonly svc: FileUploadService) {}

  /**
   * Never rejects — every failure comes back as an `error`/`rejected` result
   * so callers render a message instead of handling two failure channels.
   */
  async run(target: UploadTarget, file: File, handlers: UploadHandlers = {}): Promise<UploadResult> {
    this.cancelled = false;
    const { entityName, recordId, fieldName } = target;

    try {
      handlers.onPhase?.('uploading');
      handlers.onProgress?.(0);

      const checksum = await this.sha256Hex(file);
      const session = await firstValueFrom(this.svc.createSession(entityName, recordId, fieldName, {
        filename:            file.name,
        content_type:        file.type || 'application/octet-stream',
        declared_size_bytes: file.size,
        checksum_sha256:     checksum,
      }));

      await this.putWithProgress(session.upload_url, file, handlers);

      const finalized = await firstValueFrom(
        this.svc.finalize(entityName, recordId, fieldName, session.session_id),
      );
      if (finalized.status === 'rejected') {
        return {
          kind: 'rejected',
          message: 'Upload was rejected: the uploaded file did not match what was declared.',
        };
      }

      handlers.onPhase?.('processing');
      return await this.pollUntilSettled(target, session.session_id);
    } catch (err) {
      return { kind: 'error', message: (err as ApiError)?.message ?? 'Upload failed.' };
    }
  }

  /** Stops an in-flight poll loop — call from the host component's ngOnDestroy. */
  cancel(): void {
    this.cancelled = true;
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private putWithProgress(uploadUrl: string, file: File, handlers: UploadHandlers): Promise<void> {
    return new Promise((resolve, reject) => {
      this.svc.putToStorage(uploadUrl, file).subscribe({
        next: event => {
          if (event.type === HttpEventType.UploadProgress && event.total) {
            handlers.onProgress?.(Math.round((100 * event.loaded) / event.total));
          } else if (event.type === HttpEventType.Response) {
            resolve();
          }
        },
        error: () => reject(new Error('Upload to storage failed.')),
      });
    });
  }

  private async pollUntilSettled(target: UploadTarget, sessionId: string): Promise<UploadResult> {
    const { entityName, recordId, fieldName } = target;

    for (let attempt = 0; attempt < POLL_MAX_ATTEMPTS; attempt++) {
      if (this.cancelled) return { kind: 'error', message: 'Upload cancelled.' };

      let status;
      try {
        status = await firstValueFrom(this.svc.getStatus(entityName, recordId, fieldName, sessionId));
      } catch {
        return { kind: 'error', message: 'Could not check scan status.' };
      }

      if (status.status === 'clean' && status.final_key) {
        return { kind: 'clean', finalKey: status.final_key };
      }
      if (status.status === 'rejected') {
        return { kind: 'rejected', message: status.reject_reason ?? 'File was rejected.' };
      }

      await this.delay(POLL_INTERVAL_MS);
    }

    return {
      kind: 'error',
      message: 'Still scanning — reload this record in a moment to check again.',
    };
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => {
      this.pollTimer = setTimeout(resolve, ms);
    });
  }

  private async sha256Hex(file: File): Promise<string> {
    const buf = await file.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
}
