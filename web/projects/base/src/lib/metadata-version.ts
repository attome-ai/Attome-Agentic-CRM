import { HttpInterceptorFn, HttpResponse } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Subject, tap } from 'rxjs';

/** The response header naming the metadata version the answering node serves (Y8-T7). */
export const METADATA_VERSION_HEADER = 'attome-metadata-version';

/**
 * Y8-T8: the metadata version the server last reported. The first value is
 * the baseline; a different one later means the model changed while the app
 * was open, and `changes` emits so cached plans are dropped and open forms
 * can warn.
 */
@Injectable({ providedIn: 'root' })
export class MetadataVersion {
  private readonly current = signal<number | null>(null);
  /** The version the app started with, or last acknowledged. */
  readonly version = this.current.asReadonly();
  /** The new version, each time it changes after the first. */
  readonly changes = new Subject<number>();

  /** Records a version a response reported. */
  observe(raw: string | null): void {
    const value = raw === null ? NaN : Number(raw);
    if (!Number.isFinite(value) || value <= 0) return;
    const before = this.current();
    // A node behind the others reports an older version; only newer counts.
    if (before !== null && value <= before) return;
    this.current.set(value);
    if (before !== null) this.changes.next(value);
  }
}

/** Reads `Attome-Metadata-Version` off every API response. */
export const metadataVersionInterceptor: HttpInterceptorFn = (req, next) => {
  const versions = inject(MetadataVersion);
  return next(req).pipe(
    tap(event => {
      if (event instanceof HttpResponse) versions.observe(event.headers.get(METADATA_VERSION_HEADER));
    }),
  );
};
