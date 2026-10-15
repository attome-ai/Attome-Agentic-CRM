import { Injectable, inject, signal } from '@angular/core';
import { LiveChannel } from '@attome/base';

import { ModelService } from './model.service';

/**
 * The live channel's model notices (roadmap Y14-T3): when published metadata
 * changes the server sends `model-version`, and the cached render plans are
 * dropped so the next read revalidates them (Y14-T2). A reconnect's `hello`
 * carrying a different version counts as a change too. The connection itself
 * is `@attome/base`'s `LiveChannel`, shared with the record changes lists
 * watch (A13-T4).
 */
@Injectable({ providedIn: 'root' })
export class LiveService {
  private readonly model = inject(ModelService);
  private readonly channel = inject(LiveChannel);
  private listening = false;

  /** The published model's version stamp, once the server has sent it. */
  readonly modelVersion = signal<string | null>(null);

  /** Opens the channel once; a no-op where `EventSource` does not exist. */
  connect(): void {
    if (!this.listening) {
      this.listening = true;
      this.channel.modelFrames.subscribe(data => this.receive(data));
    }
    this.channel.connect();
  }

  disconnect(): void {
    this.channel.disconnect();
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
