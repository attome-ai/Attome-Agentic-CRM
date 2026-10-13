import { Injectable } from '@angular/core';
import { Observable, Subject } from 'rxjs';

/**
 * PERF-3 (PLATFORM-REVIEW-2026-08-24 4) - fans out "an admin just changed
 * entity metadata" so caches of `GET /api/v1/schema/{logicalname}` can drop
 * what they hold.
 *
 * It lives here, in `@attome/xrm/core/admin/data`, rather than next to the
 * cache that consumes it, because of D-314's packaging rule: an entry point
 * may import a sibling's `/data` entry point, never its component barrel.
 * `@attome/xrm/core/entity` is a component barrel (the ~264 kB shared widget
 * chunk), so `AdminService` must not reach into it - but `EntityService` can
 * reach here, and that is the direction the dependency takes.
 *
 * Deliberately coarse: it carries no payload and consumers clear everything.
 * `AdminService`'s mutations are keyed by entity *id* while the schema route is
 * keyed by *logicalname*, so a targeted signal would need an id-to-name map
 * that would itself go stale. Metadata edits are rare and admin-initiated, so
 * dropping a handful of cached schemas costs one refetch per open form.
 */
@Injectable({ providedIn: 'root' })
export class EntityMetadataChangeService {
  private readonly changed = new Subject<void>();

  /** Emits once per committed entity/attribute metadata mutation. */
  readonly changed$: Observable<void> = this.changed.asObservable();

  notify(): void {
    this.changed.next();
  }
}
