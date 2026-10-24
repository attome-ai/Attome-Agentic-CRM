import { Signal, WritableSignal, computed, signal } from '@angular/core';

import { EditCommand, applyCommand, inverseOf } from './commands';

interface Step { command: EditCommand; inverse: EditCommand; }

/**
 * Y14-T1: one document under edit, with unlimited undo and redo. Every
 * change is an edit command, so what was done since the last save is the
 * command list the server takes (`POST /api/v1/admin/model/{kind}/{id}/commands`):
 * undoing a step adds its inverse, never rewrites history already sent.
 */
export class CommandStack<T> {
  private readonly current: WritableSignal<T>;
  private readonly done = signal<Step[]>([]);
  private readonly undone = signal<Step[]>([]);
  /** Commands applied since the last save, in order (undos included as their inverses). */
  private readonly unsaved = signal<EditCommand[]>([]);

  readonly doc: Signal<T>;
  readonly canUndo = computed(() => this.done().length > 0);
  readonly canRedo = computed(() => this.undone().length > 0);
  readonly dirty = computed(() => this.unsaved().length > 0);

  constructor(initial: T) {
    this.current = signal<T>(initial);
    this.doc = this.current.asReadonly();
  }

  /** Applies `command`; a command that does not apply is refused and nothing changes. */
  exec(command: EditCommand): boolean {
    const before = this.current();
    let after: T;
    let inverse: EditCommand;
    try {
      inverse = inverseOf(before, command);
      after = applyCommand(before, command);
    } catch {
      return false;
    }
    this.current.set(after);
    this.done.update(d => [...d, { command, inverse }]);
    this.undone.set([]);
    this.unsaved.update(u => [...u, command]);
    return true;
  }

  undo(): boolean {
    const step = this.done().at(-1);
    if (!step) return false;
    this.current.set(applyCommand(this.current(), step.inverse));
    this.done.update(d => d.slice(0, -1));
    this.undone.update(u => [...u, step]);
    this.unsaved.update(u => [...u, step.inverse]);
    return true;
  }

  redo(): boolean {
    const step = this.undone().at(-1);
    if (!step) return false;
    this.current.set(applyCommand(this.current(), step.command));
    this.undone.update(u => u.slice(0, -1));
    this.done.update(d => [...d, step]);
    this.unsaved.update(u => [...u, step.command]);
    return true;
  }

  /** The commands to send, and they count as saved from now on. */
  takeUnsaved(): EditCommand[] {
    const out = this.unsaved();
    this.unsaved.set([]);
    return out;
  }

  /** Starts over from a document the server returned. */
  reset(doc: T): void {
    this.current.set(doc);
    this.done.set([]);
    this.undone.set([]);
    this.unsaved.set([]);
  }
}
