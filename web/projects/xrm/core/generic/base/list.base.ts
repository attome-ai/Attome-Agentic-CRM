import { Directive, signal } from '@angular/core';

/** Shared state and state transitions for list components. */
@Directive()
export abstract class ListBase<T> {
  readonly records = signal<T[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  protected beginLoad(): void {
    this.loading.set(true);
    this.error.set(null);
  }

  protected completeLoad(records: T[]): void {
    this.records.set(records);
    this.loading.set(false);
  }

  protected failLoad(message: string): void {
    this.error.set(message);
    this.loading.set(false);
  }
}
