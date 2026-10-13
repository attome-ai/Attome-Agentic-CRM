/**
 * A bounded undo/redo stack over full snapshots of type `T` — no DOM
 * dependency, no Angular import. Coarse (snapshot the whole document rather
 * than an inverse per-field operation) but simple, matching the Page
 * Editor's own draft-model doc comment: cheap at this document's size
 * (a page record plus a handful of widgets).
 *
 * `push` always clears the redo stack — the standard editor convention that
 * a new edit made after undoing invalidates whatever redo history followed
 * the undone state. Both stacks are bounded to `maxEntries` (default 50):
 * pushing past the bound drops the oldest entry instead of growing forever.
 */
export class DraftHistory<T> {
  private undoStack: T[] = [];
  private redoStack: T[] = [];

  constructor(private readonly maxEntries = 50) {}

  get canUndo(): boolean {
    return this.undoStack.length > 0;
  }

  get canRedo(): boolean {
    return this.redoStack.length > 0;
  }

  /** Records `snapshot` as the state `undo()` will return to next, and
   * clears the redo stack. */
  push(snapshot: T): void {
    this.undoStack.push(snapshot);
    if (this.undoStack.length > this.maxEntries) {
      this.undoStack.shift();
    }
    this.redoStack = [];
  }

  /** Moves `current` onto the redo stack and returns the snapshot to
   * restore, or `null` when there is nothing to undo (the stack is
   * untouched in that case). */
  undo(current: T): T | null {
    const prev = this.undoStack.pop();
    if (prev === undefined) return null;
    this.redoStack.push(current);
    if (this.redoStack.length > this.maxEntries) {
      this.redoStack.shift();
    }
    return prev;
  }

  /** Moves `current` onto the undo stack and returns the snapshot to
   * restore, or `null` when there is nothing to redo (the stack is
   * untouched in that case). */
  redo(current: T): T | null {
    const next = this.redoStack.pop();
    if (next === undefined) return null;
    this.undoStack.push(current);
    if (this.undoStack.length > this.maxEntries) {
      this.undoStack.shift();
    }
    return next;
  }

  /** Discards all undo/redo history. */
  clear(): void {
    this.undoStack = [];
    this.redoStack = [];
  }
}
