/**
 * NGB-4.3 — one Escape key, one handler.
 *
 * The dialog host and the step-up prompt are both modal, both listen for
 * Escape on the document, and they can be open at the same time (a step-up is
 * triggered from inside a screen that may already have a confirm dialog up).
 * Two document listeners would each close their own modal, so one keystroke
 * dismissed two surfaces — the keyboard equivalent of the backdrop-click bug
 * the dialog host already avoids.
 *
 * The fix is a tiny LIFO stack rather than a new service: each modal pushes a
 * handle when it opens and asks `isTop()` before acting on Escape. Only the
 * last one opened answers. `release()` is idempotent so a component's effect
 * cleanup can call it without tracking whether it already ran.
 *
 * Module-level state is deliberate (like the focus utility it sits beside):
 * modals are singletons per document, and Vitest resets the DOM between spec
 * files, so a leaked handle would only ever come from a component that forgot
 * to release — which is what the spec covers.
 */

export interface ModalHandle {
  /** True while this modal is the most recently opened one still open. */
  isTop(): boolean;
  /** Removes this modal from the stack. Safe to call more than once. */
  release(): void;
}

const openModals: number[] = [];
let nextId = 0;

/** Registers a modal as open and returns the handle that owns its Escape key. */
export function pushModal(): ModalHandle {
  const id = ++nextId;
  openModals.push(id);
  let released = false;

  return {
    isTop: () => openModals[openModals.length - 1] === id,
    release: () => {
      if (released) return;
      released = true;
      const at = openModals.indexOf(id);
      if (at >= 0) openModals.splice(at, 1);
    },
  };
}

/** Test seam: the number of modals currently registered. */
export function openModalCount(): number {
  return openModals.length;
}
