import {
  ChangeDetectionStrategy, Component, ElementRef, OnDestroy, OnInit, SecurityContext,
  inject, input, signal, viewChild,
} from '@angular/core';
import {
  AbstractControl, ControlContainer, FormGroup, FormGroupDirective,
} from '@angular/forms';
import { DomSanitizer } from '@angular/platform-browser';
import { Subscription } from 'rxjs';
import { TranslatePipe } from '@attome/base';

/** Inline elements the toolbar wraps a selection in. */
type InlineTag = 'strong' | 'em' | 'u';

/** The link schemes the server keeps (`attome_html::RICH_TEXT_URL_SCHEMES`). */
const SAFE_LINK = /^(https?:|mailto:|tel:)/i;

/**
 * U9 (D-605) — the editor for a `rich_text` field: a `contenteditable`
 * surface and a small allow-listed toolbar (bold, italic, underline,
 * bulleted/numbered list, link, clear formatting). No editor library and no
 * `document.execCommand`: each command is a few lines over the Selection /
 * Range API, and it can only produce elements the server's allow-list keeps
 * anyway.
 *
 * **The client is not the security boundary.** The server sanitizes every
 * write (`attome_html::sanitize_rich_text`); this component additionally
 * renders stored HTML through Angular's `DomSanitizer` (`SecurityContext.HTML`)
 * before it ever reaches the DOM, so a value that bypassed the server (or a
 * stale row written before the field was rich text) still cannot run script.
 *
 * Reads and writes the host form's control (`ControlContainer`, the pattern
 * `image-upload.component.ts` uses), so a host template only passes the
 * control name.
 */
@Component({
  selector: 'xrm-rich-text-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  viewProviders: [{ provide: ControlContainer, useExisting: FormGroupDirective }],
  styleUrls: ['./rich-text-editor.component.css'],
  templateUrl: './rich-text-editor.component.html',
})
export class RichTextEditorComponent implements OnInit, OnDestroy {
  /** Logicalname of the `rich_text` field — the form control key. */
  readonly fieldName = input.required<string>();
  /** Accessible name of the editing surface. */
  readonly label     = input('');

  private readonly surface   = viewChild.required<ElementRef<HTMLDivElement>>('surface');
  private readonly cc        = inject(ControlContainer);
  private readonly sanitizer = inject(DomSanitizer);

  readonly linkOpen = signal(false);
  readonly linkUrl  = signal('');
  readonly linkInvalid = signal(false);

  /** The selection a link will wrap, saved when the link box opens (focusing
   * its input clears the document selection). */
  private savedRange: Range | null = null;
  /** Set while this component writes the control, so its own echo through
   * `valueChanges` does not re-render the surface and move the caret. */
  private writing = false;
  private sub?: Subscription;

  get ctrl(): AbstractControl {
    return (this.cc.control as FormGroup).get(this.fieldName())!;
  }

  ngOnInit(): void {
    this.render(this.ctrl?.value);
    this.sub = this.ctrl?.valueChanges.subscribe(v => {
      if (!this.writing) this.render(v);
    });
  }

  ngOnDestroy(): void { this.sub?.unsubscribe(); }

  /** Writes `value` into the surface through Angular's HTML sanitizer. */
  private render(value: unknown): void {
    const html = typeof value === 'string' ? value : '';
    this.surface().nativeElement.innerHTML =
      this.sanitizer.sanitize(SecurityContext.HTML, html) ?? '';
  }

  /** The surface's current HTML → the control (empty editor → null). */
  sync(): void {
    const el = this.surface().nativeElement;
    const hasContent = !!el.textContent?.trim() || el.querySelector('li, a') !== null;
    const html = hasContent ? el.innerHTML : '';
    this.writing = true;
    try {
      this.ctrl.setValue(html === '' ? null : html);
      this.ctrl.markAsDirty();
    } finally {
      this.writing = false;
    }
  }

  onBlur(): void { this.ctrl.markAsTouched(); }

  /** The current selection's range, if it lies inside this editor. */
  private currentRange(): Range | null {
    const sel = globalThis.getSelection?.();
    if (!sel || sel.rangeCount === 0) return null;
    const range = sel.getRangeAt(0);
    return this.surface().nativeElement.contains(range.commonAncestorContainer) ? range : null;
  }

  private selectNode(node: Node): void {
    const sel = globalThis.getSelection?.();
    if (!sel) return;
    const range = document.createRange();
    range.selectNodeContents(node);
    sel.removeAllRanges();
    sel.addRange(range);
  }

  /** Bold / italic / underline: wraps the selected content. */
  wrap(tag: InlineTag): void {
    const range = this.currentRange();
    if (!range || range.collapsed) return;
    const el = document.createElement(tag);
    el.appendChild(range.extractContents());
    range.insertNode(el);
    this.selectNode(el);
    this.sync();
  }

  /** Bulleted / numbered list: the selection becomes one list item (an empty
   * one when nothing is selected). */
  list(tag: 'ul' | 'ol'): void {
    const range = this.currentRange() ?? this.endRange();
    const listEl = document.createElement(tag);
    const item = document.createElement('li');
    if (!range.collapsed) item.appendChild(range.extractContents());
    listEl.appendChild(item);
    range.insertNode(listEl);
    this.selectNode(item);
    this.sync();
  }

  /** Replaces the selection with its plain text. */
  clearFormatting(): void {
    const range = this.currentRange();
    if (!range || range.collapsed) return;
    const text = document.createTextNode(range.toString());
    range.deleteContents();
    range.insertNode(text);
    this.sync();
  }

  openLink(): void {
    const range = this.currentRange();
    if (!range || range.collapsed) return;
    this.savedRange = range.cloneRange();
    this.linkUrl.set('https://');
    this.linkInvalid.set(false);
    this.linkOpen.set(true);
  }

  cancelLink(): void {
    this.linkOpen.set(false);
    this.savedRange = null;
  }

  /** Wraps the saved selection in `<a href>` — only for a scheme the server
   * keeps, so the editor never produces a link the save would strip. */
  applyLink(): void {
    const url = this.linkUrl().trim();
    const range = this.savedRange;
    if (!SAFE_LINK.test(url)) { this.linkInvalid.set(true); return; }
    if (!range || !this.surface().nativeElement.contains(range.commonAncestorContainer)) {
      this.cancelLink();
      return;
    }
    const a = document.createElement('a');
    a.setAttribute('href', url);
    a.appendChild(range.extractContents());
    range.insertNode(a);
    this.cancelLink();
    this.sync();
  }

  /** A collapsed range at the end of the surface — where a list goes when
   * the caret is not inside the editor. */
  private endRange(): Range {
    const range = document.createRange();
    range.selectNodeContents(this.surface().nativeElement);
    range.collapse(false);
    return range;
  }
}
