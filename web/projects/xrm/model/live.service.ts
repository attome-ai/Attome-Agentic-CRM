import { Injectable, inject, signal } from '@angular/core';
import { ATTOME_CONFIG } from '@attome/base';

import { ModelService } from './model.service';

/**
 * The live channel (roadmap Y14-T3, first slice): one `EventSource` on
 * `GET /api/v1/live`. When published metadata changes the server sends
 * `model-version`, and the cached render plans are dropped so the next
 * read revalidates them (Y14-T2). The browser reconnects by itself; a
 * reconnect's `hello` carrying a different version counts as a change too.
 */
@Injectable({ providedIn: 'root' })
export class LiveService {
  private readonly model = inject(ModelService);
  private readonly config = inject(ATTOME_CONFIG);
  private source: EventSource | null = null;

  /** The published model's version stamp, once the server has sent it. */
  readonly modelVersion = signal<string | null>(null);

  /** Opens the channel once; a no-op where `EventSource` does not exist. */
  connect(): void {
    if (this.source || typeof EventSource === 'undefined') return;
    const source = new EventSource(`${this.config.apiUrl}/api/v1/live`, { withCredentials: true });
    source.addEventListener('hello', event => this.receive((event as MessageEvent<string>).data));
    source.addEventListener('model-version', event => this.receive((event as MessageEvent<string>).data));
    this.source = source;
  }

  disconnect(): void {
    this.source?.close();
    this.source = null;
  }

  /** Applies one frame's `{model_version}`. */
  receive(data: string): void {
    let version: string | null;
    try {
      const parsed = JSON.parse(data) as { model_version?: unknown };
      version = typeof parsed.model_version === 'string' ? parsed.model_version : null;
    } catch {
      return;
    }
    if (version === null) return;
    const previous = this.modelVersion();
    if (previous !== null && previous !== version) {
      this.model.forgetPlans();
    }
    this.modelVersion.set(version);
  }
}
