import { Injectable, inject } from '@angular/core';
import { SdkService } from '@attome/base';
import { Observable, catchError, map, of, shareReplay } from 'rxjs';

/** What the deployment's vision model read (`POST /api/v1/ai/read-text`). */
export interface ReadText {
  text: string;
  model: string;
}

/** The longest image edge sent: enough for a label or a page, small enough to send fast. */
export const READ_TEXT_MAX_EDGE = 1600;

/**
 * B16-T14 / N21: reading the text of a captured image through the
 * deployment's own vision model. `available()` asks once per session whether
 * this deployment can (`GET /api/v1/ai/read-text`); a failed probe counts as
 * no, so the button stays hidden. `read()` sends one image only when the
 * person asks for it; nothing is sent while the camera merely runs.
 */
@Injectable({ providedIn: 'root' })
export class ReadTextService {
  private readonly sdk = inject(SdkService);
  private probe: Observable<boolean> | null = null;

  available(): Observable<boolean> {
    this.probe ??= this.sdk.get<{ available: boolean }>('/api/v1/ai/read-text').pipe(
      map(r => r.available === true),
      catchError(() => of(false)),
      shareReplay(1),
    );
    return this.probe;
  }

  read(image: string, mediaType: string, language?: 'ar' | 'en'): Observable<ReadText> {
    return this.sdk.post<ReadText>('/api/v1/ai/read-text', { body: { image, media_type: mediaType, language } });
  }
}

/**
 * The video's current frame as base64 JPEG, scaled so its longer edge is at
 * most `maxEdge`; `null` when the video has no frame yet. Browser only.
 */
export function captureFrame(video: HTMLVideoElement, doc: Document, maxEdge = READ_TEXT_MAX_EDGE): string | null {
  const width = video.videoWidth;
  const height = video.videoHeight;
  if (!width || !height) return null;
  const scale = Math.min(1, maxEdge / Math.max(width, height));
  const canvas = doc.createElement('canvas');
  canvas.width = Math.round(width * scale);
  canvas.height = Math.round(height * scale);
  const context = canvas.getContext('2d');
  if (!context) return null;
  context.drawImage(video, 0, 0, canvas.width, canvas.height);
  const url = canvas.toDataURL('image/jpeg', 0.9);
  const comma = url.indexOf(',');
  return comma >= 0 ? url.slice(comma + 1) : null;
}
