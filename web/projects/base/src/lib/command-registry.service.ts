import { Injectable, signal } from '@angular/core';

/** One command the command palette (Ctrl+K) offers. */
export interface PaletteCommand {
  /** Stable id; the palette ranks commands by how often each id is used. */
  id: string;
  /** The translation key of its name. */
  labelKey: string;
  /** A Line Awesome class, for example `las la-save`. */
  icon?: string;
  /** True for the open page's own commands (a record's actions): listed first. */
  context?: boolean;
  run: () => void;
}

/**
 * B10-T1: the commands the palette offers right now. A page registers its
 * own while it is open and removes them on leaving, so the palette lists the
 * open record's actions first.
 */
@Injectable({ providedIn: 'root' })
export class CommandRegistry {
  private readonly list = signal<readonly PaletteCommand[]>([]);
  readonly commands = this.list.asReadonly();

  /** Adds commands; returns the function that removes them again. */
  register(...commands: PaletteCommand[]): () => void {
    this.list.update(current => [...current, ...commands]);
    return () => this.list.update(current => current.filter(c => !commands.includes(c)));
  }
}
