import { HttpEventType, type HttpEvent } from '@angular/common/http';
import { of, throwError } from 'rxjs';
import { describe, expect, it } from 'vitest';

import type { FileUploadService } from './file-upload.service';
import { UploadPipeline } from './upload-pipeline';

describe('UploadPipeline multipart (AB7-T6)', () => {
  it('after a network error asks what arrived and sends only the missing parts', async () => {
    const puts: string[] = [];
    let failedOnce = false;
    let completed = false;
    const svc = {
      startMultipart: () => of({ session_id: 's1', part_size: 4, part_count: 3 }),
      partUrl: (_session: string, n: number) =>
        of({ part: n, upload_url: `u${n}`, expires_in_secs: 3600 }),
      putPart: (url: string) => {
        puts.push(url);
        if (url === 'u2' && !failedOnce) {
          failedOnce = true;
          return throwError(() => new Error('network'));
        }
        return of({ type: HttpEventType.Response } as HttpEvent<unknown>);
      },
      multipartStatus: () =>
        of({ session_id: 's1', status: 'open', part_size: 4, part_count: 3, received: [1] }),
      completeMultipart: () => {
        completed = true;
        return of({ session_id: 's1', size: 10, checksum_sha256: '' });
      },
    } as unknown as FileUploadService;

    const pipeline = new UploadPipeline(svc);
    const session = await pipeline.uploadInParts(
      { entityName: 'contact', recordId: 'r1', fieldName: 'video' },
      new Blob(['0123456789']),
      { filename: 'v.mp4', content_type: 'video/mp4', declared_size_bytes: 10 },
    );

    expect(session).toBe('s1');
    // Part 1 is not sent again: the server said it arrived.
    expect(puts).toEqual(['u1', 'u2', 'u2', 'u3']);
    expect(completed).toBe(true);
  });
});
