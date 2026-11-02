import { Injectable, signal } from '@angular/core';

/**
 * Solution 7 (D-785): the changeset every mutating request names through
 * `X-Attome-Changeset`, or `null` to send none (the server then uses the
 * caller's single open changeset, or refuses or auto-records per its mode).
 * Set only through `set`; nothing picks one implicitly. Y9-T3: its own
 * service, so both HTTP clients (`ApiService`, `SdkService`) and the
 * changeset picker read one value without depending on each other.
 */
@Injectable({ providedIn: 'root' })
export class ChangesetState {
  private readonly id = signal<string | null>(null);
  readonly active = this.id.asReadonly();

  /**
   * Names the changeset later mutating requests record into; `null` clears
   * it. An empty or whitespace-only id is treated as `null` so a blank picker
   * never sends a header the server would reject as malformed (422).
   */
  set(id: string | null): void {
    const trimmed = id?.trim() ?? '';
    this.id.set(trimmed.length > 0 ? trimmed : null);
  }
}
