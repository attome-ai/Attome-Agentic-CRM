/**
 * NGB-3.1 / OD-9 — the one focus utility the modal hosts share.
 *
 * A local ~40-line helper rather than `@angular/cdk`'s `ConfigurableFocusTrap`:
 * one behaviour does not justify a new runtime peer (OD-9 rejected the CDK for
 * exactly this).
 *
 * `trapFocus` keeps Tab and Shift+Tab inside `root` and returns a teardown
 * that removes the listener and restores focus to whatever was focused before
 * the modal opened — the trigger, normally. Without the restore, closing a
 * dialog drops the keyboard user back on `<body>` (NGB-F16).
 */

const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

/** Every focusable descendant of `root`, in document order, minus hidden ones. */
export function focusableElements(root: HTMLElement): HTMLElement[] {
  const found = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE));
  return found.filter(el =>
    !el.hasAttribute('disabled')
    && el.getAttribute('aria-hidden') !== 'true'
    // `offsetParent === null` is false for a `position: fixed` element, so it
    // cannot be the only visibility test; `hidden` covers the explicit case.
    && el.getAttribute('hidden') === null,
  );
}

/**
 * Traps Tab/Shift+Tab inside `root`. Returns the teardown: it removes the
 * listener and returns focus to the element that was focused when the trap was
 * installed.
 */
export function trapFocus(root: HTMLElement): () => void {
  const doc = root.ownerDocument;
  const previouslyFocused = doc.activeElement as HTMLElement | null;

  const onKeydown = (event: KeyboardEvent) => {
    if (event.key !== 'Tab') return;
    const items = focusableElements(root);
    if (items.length === 0) {
      // Nothing to move to: keep focus where it is rather than letting Tab
      // walk out of the modal into the page behind it.
      event.preventDefault();
      return;
    }
    const first = items[0];
    const last  = items[items.length - 1];
    const active = doc.activeElement;
    const inside = active instanceof HTMLElement && root.contains(active);

    if (event.shiftKey) {
      if (!inside || active === first) {
        event.preventDefault();
        last.focus();
      }
    } else if (!inside || active === last) {
      event.preventDefault();
      first.focus();
    }
  };

  root.addEventListener('keydown', onKeydown);

  return () => {
    root.removeEventListener('keydown', onKeydown);
    if (previouslyFocused && previouslyFocused.isConnected && typeof previouslyFocused.focus === 'function') {
      previouslyFocused.focus();
    }
  };
}
