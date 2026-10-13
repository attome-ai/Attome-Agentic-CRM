import { describe, expect, it } from 'vitest';
import { openModalCount, pushModal } from './modal-stack';

/** NGB-4.3 — only the top-most modal answers Escape. */
describe('modal-stack', () => {
  it('makes the most recently opened modal the top one', () => {
    const first  = pushModal();
    const second = pushModal();
    try {
      expect(first.isTop()).toBe(false);
      expect(second.isTop()).toBe(true);
    } finally {
      second.release();
      first.release();
    }
  });

  it('hands Escape back to the modal below when the top one closes', () => {
    const first  = pushModal();
    const second = pushModal();
    second.release();
    try {
      expect(first.isTop()).toBe(true);
    } finally {
      first.release();
    }
  });

  it('ignores a second release and leaves the stack balanced', () => {
    const before = openModalCount();
    const handle = pushModal();
    expect(openModalCount()).toBe(before + 1);
    handle.release();
    handle.release();
    expect(openModalCount()).toBe(before);
    expect(handle.isTop()).toBe(false);
  });

  it('never reports an unregistered modal as top', () => {
    const handle = pushModal();
    handle.release();
    expect(handle.isTop()).toBe(false);
  });
});
