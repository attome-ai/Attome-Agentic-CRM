import { Injectable, signal } from '@angular/core';

/** One keyboard shortcut as the `?` help lists it. */
export interface Shortcut {
  /** How it is pressed, for example `Ctrl+1…9` or `Shift Shift`. */
  keys: string;
  /** The translation key of what it does. */
  labelKey: string;
}

/**
 * B10-T2: the shortcuts the app offers right now. The shell registers its
 * own; a page registers its while it is open and unregisters on leaving, so
 * the `?` help always lists what works here.
 */
@Injectable({ providedIn: 'root' })
export class ShortcutRegistry {
  private readonly list = signal<readonly Shortcut[]>([]);
  readonly shortcuts = this.list.asReadonly();

  /** Adds shortcuts; returns the function that removes them again. */
  register(...shortcuts: Shortcut[]): () => void {
    this.list.update(current => [...current, ...shortcuts]);
    return () => this.list.update(current => current.filter(s => !shortcuts.includes(s)));
  }
}

/** True when a key press is typing into a field, which shortcuts leave alone. */
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable === true;
}
