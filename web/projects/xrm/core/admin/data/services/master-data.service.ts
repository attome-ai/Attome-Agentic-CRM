import { inject, Injectable } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ApiService, Page } from '@attome/base';

/**
 * L1 master data over `crates/engine/attome-api/src/master_admin.rs`: where
 * a golden record's values came from, its source system ids, the held
 * contributions, and the steward's pin, release, reject and detach. The
 * reads need `{entity}.read`; the steward actions an administrator or a
 * steward of the entity's data domain. Lists are one-based (D-793).
 */

/** Where one attribute's golden value came from (`MasterProvenance`). */
export interface MasterProvenance {
  attribute: string;
  /** `source_system_rank`, `most_recent` or `pinned`. */
  rule: string;
  chosen_at: string;
  pinned: boolean;
  contribution_id?: string | null;
  source_system?: string | null;
  external_id?: string | null;
  received_at?: string | null;
}

/** One source system's id of a golden record (`MasterSystemId`). */
export interface MasterSystemId {
  contribution_id: string;
  source_system: string;
  external_id: string;
  status: MasterContributionStatus;
  received_at: string;
}

export type MasterContributionStatus = 'attached' | 'held' | 'detached';

/** A held contribution waiting for a steward (`MasterHeldContribution`). */
export interface MasterHeldContribution {
  entity: string;
  id: string;
  source_system: string;
  external_id: string;
  received_at: string;
  held_reason?: string | null;
}

/** The golden record a source system's id belongs to (`MasterXrefGolden`). */
export interface MasterXrefGolden {
  golden_id: string;
  status: MasterContributionStatus;
}

/** A field of the golden record's entity, as the panel labels it. */
export interface MasterField {
  name: string;
  display_name: string;
}

/** What a release or detach did (`MasterRebuildQueued`). */
export interface MasterRebuildQueued {
  golden_id: string;
  rebuild_queued: boolean;
}

@Injectable({ providedIn: 'root' })
export class MasterDataService {
  private readonly api = inject(ApiService);

  private base(entity: string): string {
    return `/api/v1/master/${encodeURIComponent(entity)}`;
  }

  /** The golden record's values as the caller reads them. */
  values(entity: string, id: string): Observable<Record<string, unknown>> {
    return this.api
      .get<{ data: Record<string, unknown> }>(`/api/v1/${encodeURIComponent(entity)}/${encodeURIComponent(id)}`)
      .pipe(map(r => r.data ?? {}));
  }

  /** The entity's fields, for their labels. */
  fields(entity: string): Observable<MasterField[]> {
    return this.api
      .get<{ fields: MasterField[] }>(`/api/v1/schema/${encodeURIComponent(entity)}`)
      .pipe(map(s => s.fields ?? []));
  }

  provenance(entity: string, id: string): Observable<Page<MasterProvenance>> {
    return this.api.get<Page<MasterProvenance>>(`${this.base(entity)}/${encodeURIComponent(id)}/provenance`);
  }

  systemIds(entity: string, id: string): Observable<Page<MasterSystemId>> {
    return this.api.get<Page<MasterSystemId>>(`${this.base(entity)}/${encodeURIComponent(id)}/xref`);
  }

  lookup(entity: string, system: string, externalId: string): Observable<MasterXrefGolden> {
    return this.api.get<MasterXrefGolden>(`${this.base(entity)}/xref`, {
      system, external_id: externalId,
    });
  }

  held(page = 1, pageSize = 50): Observable<Page<MasterHeldContribution>> {
    return this.api.get<Page<MasterHeldContribution>>('/api/v1/master/held', {
      page: String(page), page_size: String(pageSize),
    });
  }

  pin(entity: string, id: string, attribute: string): Observable<void> {
    return this.api.post<void>(`${this.base(entity)}/${encodeURIComponent(id)}/pins`, { attribute });
  }

  unpin(entity: string, id: string, attribute: string): Observable<void> {
    return this.api.delete(
      `${this.base(entity)}/${encodeURIComponent(id)}/pins/${encodeURIComponent(attribute)}`,
    );
  }

  /** Validates the stored payload again and attaches it. */
  release(entity: string, contribution: string): Observable<MasterRebuildQueued> {
    return this.api.post<MasterRebuildQueued>(
      `${this.base(entity)}/contributions/${encodeURIComponent(contribution)}/release`, {},
    );
  }

  reject(entity: string, contribution: string, reason: string): Observable<void> {
    return this.api.post<void>(
      `${this.base(entity)}/contributions/${encodeURIComponent(contribution)}/reject`, { reason },
    );
  }

  detach(entity: string, contribution: string): Observable<MasterRebuildQueued> {
    return this.api.post<MasterRebuildQueued>(
      `${this.base(entity)}/contributions/${encodeURIComponent(contribution)}/detach`, {},
    );
  }
}
