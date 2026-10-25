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

/** AB7-T6: files at least this large go up in resumable parts (Z6-T2). */
export const MULTIPART_THRESHOLD_BYTES = 64 * 1024 * 1024;
/** Rounds of "ask what arrived, send the rest" before an upload gives up. */
const MULTIPART_ROUNDS = 3;

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
      const request = {
        filename:            file.name,
        content_type:        file.type || 'application/octet-stream',
        declared_size_bytes: file.size,
        checksum_sha256:     checksum,
      };
      let sessionId: string;
      if (file.size >= MULTIPART_THRESHOLD_BYTES) {
        sessionId = await this.uploadInParts(target, file, request, handlers);
      } else {
        const session = await firstValueFrom(
          this.svc.createSession(entityName, recordId, fieldName, request),
        );
        await this.putWithProgress(session.upload_url, file, handlers);
        sessionId = session.session_id;
      }

      const finalized = await firstValueFrom(
        this.svc.finalize(entityName, recordId, fieldName, sessionId),
      );
      if (finalized.status === 'rejected') {
        return {
          kind: 'rejected',
          message: 'Upload was rejected: the uploaded file did not match what was declared.',
        };
      }

      handlers.onPhase?.('processing');
      return await this.pollUntilSettled(target, sessionId);
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

  /**
   * AB7-T6: a large file in parts. After a network error the server is asked
   * which parts arrived and only the missing ones are sent again, so an
   * interrupted upload continues from the next missing part.
   */
  async uploadInParts(
    target: UploadTarget,
    file: Blob,
    request: Parameters<FileUploadService['startMultipart']>[3],
    handlers: UploadHandlers = {},
  ): Promise<string> {
    const { entityName, recordId, fieldName } = target;
    const started = await firstValueFrom(
      this.svc.startMultipart(entityName, recordId, fieldName, request),
    );
    let received = new Set<number>();
    for (let round = 0; round < MULTIPART_ROUNDS; round++) {
      if (this.cancelled) throw new Error('Upload cancelled.');
      if (round > 0) {
        const status = await firstValueFrom(this.svc.multipartStatus(started.session_id));
        received = new Set(status.received);
      }
      try {
        for (let n = 1; n <= started.part_count; n++) {
          if (received.has(n)) continue;
          const start = (n - 1) * started.part_size;
          const part = file.slice(start, Math.min(start + started.part_size, file.size));
          const url = await firstValueFrom(this.svc.partUrl(started.session_id, n));
          await this.putPart(url.upload_url, part);
          received.add(n);
          handlers.onProgress?.(Math.round((100 * received.size) / started.part_count));
        }
        await firstValueFrom(this.svc.completeMultipart(started.session_id));
        return started.session_id;
      } catch (err) {
        if (round === MULTIPART_ROUNDS - 1) throw err;
      }
    }
    throw new Error('Upload to storage failed.');
  }

  private putPart(uploadUrl: string, part: Blob): Promise<void> {
    return new Promise((resolve, reject) => {
      this.svc.putPart(uploadUrl, part).subscribe({
        next: event => {
          if (event.type === HttpEventType.Response) resolve();
        },
        error: () => reject(new Error('Upload to storage failed.')),
      });
    });
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
