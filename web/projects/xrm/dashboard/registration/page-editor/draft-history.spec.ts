import { describe, expect, it } from 'vitest';
import { DraftHistory } from './draft-history';

describe('DraftHistory', () => {
  it('starts empty: neither undo nor redo is available', () => {
    const h = new DraftHistory<number>();
    expect(h.canUndo).toBe(false);
    expect(h.canRedo).toBe(false);
  });

  it('push records a snapshot and clears any pending redo', () => {
    const h = new DraftHistory<number>();
    h.push(1);
    expect(h.canUndo).toBe(true);
    expect(h.canRedo).toBe(false);
  });

  it('undo/redo are symmetric — redo restores exactly what undo moved away from', () => {
    const h = new DraftHistory<number>();
    h.push(1); // snapshot taken before moving from state 1 to state 2
    const prev = h.undo(2);
    expect(prev).toBe(1);
    expect(h.canUndo).toBe(false);
    expect(h.canRedo).toBe(true);

    const next = h.redo(prev!);
    expect(next).toBe(2);
    expect(h.canUndo).toBe(true);
    expect(h.canRedo).toBe(false);
  });

  it('undo returns null and leaves the stacks untouched when there is nothing to undo', () => {
    const h = new DraftHistory<number>();
    expect(h.undo(42)).toBeNull();
    expect(h.canUndo).toBe(false);
    expect(h.canRedo).toBe(false);
  });

  it('redo returns null and leaves the stacks untouched when there is nothing to redo', () => {
    const h = new DraftHistory<number>();
    h.push(1);
    expect(h.redo(2)).toBeNull();
    expect(h.canUndo).toBe(true);
  });

  it('a chain of undos then redos round-trips through every intermediate state in order', () => {
    const h = new DraftHistory<number>();
    let state = 0;
    for (const next of [1, 2, 3]) {
      h.push(state);
      state = next;
    }
    // state is 3, undo stack is [0, 1, 2]
    const undone: number[] = [];
    let current = state;
    while (h.canUndo) {
      current = h.undo(current)!;
      undone.push(current);
    }
    expect(undone).toEqual([2, 1, 0]);

    const redone: number[] = [];
    while (h.canRedo) {
      current = h.redo(current)!;
      redone.push(current);
    }
    expect(redone).toEqual([1, 2, 3]);
  });

  it('push after an undo clears the redo stack — a new edit invalidates the redone future', () => {
    const h = new DraftHistory<number>();
    h.push(1);
    const prev = h.undo(2);
    expect(h.canRedo).toBe(true);
    h.push(prev!);
    expect(h.canRedo).toBe(false);
  });

  it('bounds each stack to maxEntries, evicting the oldest entry first', () => {
    const h = new DraftHistory<number>(3);
    h.push(1);
    h.push(2);
    h.push(3);
    h.push(4); // 4 pushes into a max-3 undo stack — 1 should be evicted

    expect(h.undo(5)).toBe(4);
    expect(h.undo(4)).toBe(3);
    expect(h.undo(3)).toBe(2);
    expect(h.canUndo).toBe(false); // 1 was evicted, never reachable
  });

  it('bounds the redo stack the same way', () => {
    const h = new DraftHistory<number>(2);
    let current = 0;
    for (const next of [1, 2, 3]) {
      h.push(current);
      current = next;
    }
    // undo stack [0,1,2] all still fit (max 2 -> actually [1,2], 0 evicted)
    current = h.undo(current)!; // 2
    current = h.undo(current)!; // 1
    expect(h.canUndo).toBe(false); // 0 was evicted when the 3rd push happened
    // redo stack now holds [3, 2] (bounded to 2) after the two undos above
    let last = current;
    let redoCount = 0;
    while (h.canRedo) {
      last = h.redo(last)!;
      redoCount++;
    }
    expect(redoCount).toBe(2);
    expect(last).toBe(3);
  });

  it('clear discards both stacks', () => {
    const h = new DraftHistory<number>();
    h.push(1);
    h.undo(2);
    expect(h.canRedo).toBe(true);
    h.clear();
    expect(h.canUndo).toBe(false);
    expect(h.canRedo).toBe(false);
  });

  it('works over object snapshots, not just primitives (the Page Editor\'s actual use)', () => {
    interface Doc { widgets: string[] }
    const h = new DraftHistory<Doc>();
    const a: Doc = { widgets: ['w1'] };
    const b: Doc = { widgets: ['w1', 'w2'] };
    h.push(a);
    const prev = h.undo(b);
    expect(prev).toBe(a);
    expect(prev?.widgets).toEqual(['w1']);
  });
});
