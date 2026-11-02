import { Injectable, inject } from '@angular/core';
import { ApiComponents, ApiService } from '@attome/base';
import { Observable, map } from 'rxjs';

export type JourneyCounts = ApiComponents['schemas']['JourneyCounts'];
export type JourneyNodeCount = ApiComponents['schemas']['NodeCount'];
export type PersonRun = ApiComponents['schemas']['PersonRun'];
export type JourneyPublishResult = ApiComponents['schemas']['JourneyPublishResult'];
export type VersionMode = ApiComponents['schemas']['VersionMode'];

/**
 * People waiting at one node of a journey's live runs, for publishing a new
 * version (`GET .../versions/{version_id}/preview`, E8-T13).
 */
export interface NodeWaiting {
  node_id: string;
  waiting_count: number;
  exists_in_new: boolean;
  movable_count: number;
}

/** The journey routes the workflow editor reads for a journey (E8-T13). */
@Injectable({ providedIn: 'root' })
export class JourneyService {
  private readonly api = inject(ApiService);

  private base(journey: string): string {
    return `/api/v1/marketing/journeys/${encodeURIComponent(journey)}`;
  }

  /** The marketing journey record whose workflow is `logicalname`, if any. */
  forDefinition(logicalname: string): Observable<string | null> {
    return this.api
      .get<{ items: { id: string }[] }>('/api/v1/marketing_journey', {
        'filter[workflow_definition_logicalname][eq]': logicalname,
        page_size: '1',
        select: 'id',
      })
      .pipe(map(page => page.items?.[0]?.id ?? null));
  }

  /** Each node's counts, per version, with the goal conversion. */
  counts(journey: string): Observable<JourneyCounts> {
    return this.api.get<JourneyCounts>(`${this.base(journey)}/counts`);
  }

  /** One person's runs, oldest first. */
  path(journey: string, person: string): Observable<PersonRun[]> {
    return this.api
      .get<{ items: PersonRun[] }>(`${this.base(journey)}/people/${encodeURIComponent(person)}/path`)
      .pipe(map(page => page.items ?? []));
  }

  /** Who waits where, and who a move would move, before publishing `version`. */
  preview(journey: string, version: string): Observable<NodeWaiting[]> {
    return this.api
      .get<{ items: NodeWaiting[] }>(`${this.base(journey)}/versions/${encodeURIComponent(version)}/preview`)
      .pipe(map(page => page.items ?? []));
  }

  /** Publishes `version`, placing the people already in the journey as `mode` says. */
  publish(journey: string, version: string, mode: VersionMode): Observable<JourneyPublishResult> {
    return this.api.post<JourneyPublishResult>(`${this.base(journey)}/publish`, {
      version_id: version,
      version_mode: mode,
    });
  }
}
