import { ChangeDetectionStrategy, Component, ViewEncapsulation, computed, input } from '@angular/core';

import { renderNoteText } from './note-format';

/**
 * B3-T2 — a note's text with its marks formatted (`note-format.ts`).
 *
 * The markup comes from `[innerHTML]`, which emulated encapsulation never
 * reaches, so the styles are unencapsulated and every selector is under the
 * `xnp-` prefix the notes panel owns; the composer's format bar, drop
 * targets and thumbnails are styled here too, keeping the panel's own
 * stylesheet within its budget.
 */
@Component({
  selector: 'xrm-note-text',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  template: `<div class="xnp-rich" [innerHTML]="html()"></div>`,
  styles: [`
    .xnp-rich ul { margin: .25rem 0; padding-inline-start: 1.25rem; }
    .xnp-rich blockquote { margin: .25rem 0; padding-inline-start: .75rem; border-inline-start: 3px solid var(--color-border, #d0d5dd); }
    .xnp-rich code { background: var(--color-surface-muted, #f2f4f7); padding: 0 .25rem; border-radius: 4px; }
    .xnp-mention { color: var(--color-primary, #2563eb); font-weight: 600; }
    .xnp-format-bar { display: flex; gap: .25rem; margin-block-end: .25rem; }
    .xnp-format-btn { border: 1px solid var(--color-border, #d0d5dd); background: none; border-radius: 4px; cursor: pointer; }
    .xnp-dropzone-over, .xnp-composer-over { outline: 2px dashed var(--color-primary, #2563eb); }
    .xnp-att-thumb { inline-size: 2rem; block-size: 2rem; object-fit: cover; border-radius: 4px; }
  `],
})
export class NoteTextComponent {
  readonly text = input<string | null | undefined>(null);
  readonly html = computed(() => renderNoteText(this.text()));
}
