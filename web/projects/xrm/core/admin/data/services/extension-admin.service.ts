import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { SdkService } from '@attome/base';
import type { ApiComponents, Page } from '@attome/base';

/**
 * AE2-T4 — the extension admin routes (`attome_api::extension_admin`,
 * automation administrators): every version of every extension, and an
 * extension's latest runs with their time, fuel, result and log lines
 * (secrets already masked by the server).
 */
export type ExtensionVersion = ApiComponents['schemas']['ExtensionVersion'];
export type ExtensionRun = ApiComponents['schemas']['ExtensionRun'];

/** One log line of a run, as the server stores it. */
export interface ExtensionLogLine {
  level: string;
  message: string;
}

@Injectable({ providedIn: 'root' })
export class ExtensionAdminService {
  private readonly sdk = inject(SdkService);

  /** `GET /api/v1/admin/extensions`: every version, by name and newest first. */
  versions(): Observable<Page<ExtensionVersion>> {
    return this.sdk.get<Page<ExtensionVersion>>('/api/v1/admin/extensions');
  }

  /** `GET /api/v1/admin/extensions/{name}/runs`: the latest 200 runs, newest first. */
  runs(name: string): Observable<Page<ExtensionRun>> {
    return this.sdk.get<Page<ExtensionRun>>(
      `/api/v1/admin/extensions/${encodeURIComponent(name)}/runs`,
    );
  }
}
