/**
 * B3-T2 — rich notes. A note stays plain text with light marks, so search,
 * the timeline, AI and exports read it as written; the panel shows the marks
 * formatted:
 *
 * - `**bold**`, `_italic_`, `` `code` ``;
 * - a line starting `- ` is a list item, `> ` a quote;
 * - an `http(s)://` address is a link (new tab, no referrer);
 * - a mention token (`@[user:id]`, `@[team:id]`, `@[record:entity/id]`) is a
 *   chip.
 *
 * Everything is escaped first, so the only markup in the result is what this
 * file writes; Angular's sanitiser checks `[innerHTML]` again.
 */

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

/** `text` with every HTML-special character escaped. Pure. */
export function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, c => ESCAPES[c]);
}

/** The inline marks of one escaped line. Pure. */
function inline(line: string): string {
  return line
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[\s(])_([^_]+)_(?=$|[\s).,!?:;])/g, '$1<em>$2</em>')
    .replace(/@\[(user|team|record):([^\]\s]+)\]/g, (_m, kind: string, ref: string) =>
      `<span class="xnp-mention xnp-mention-${kind}" title="${ref}">@${kind === 'record' ? ref.split('/')[0] : kind}</span>`)
    .replace(/\bhttps?:\/\/[^\s<]+[^\s<.,;:!?)]/g, url =>
      `<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`);
}

/** A note's text as safe HTML with its marks formatted. Pure. */
export function renderNoteText(text: string | null | undefined): string {
  if (!text) return '';
  const out: string[] = [];
  let list = false;
  for (const raw of escapeHtml(text).split(/\r?\n/)) {
    const item = /^\s*-\s+(.*)$/.exec(raw);
    if (item) {
      if (!list) out.push('<ul>');
      list = true;
      out.push(`<li>${inline(item[1])}</li>`);
      continue;
    }
    if (list) out.push('</ul>');
    list = false;
    const quote = /^&gt;\s?(.*)$/.exec(raw);
    out.push(quote ? `<blockquote>${inline(quote[1])}</blockquote>` : `${inline(raw)}<br>`);
  }
  if (list) out.push('</ul>');
  return out.join('').replace(/(<br>)+$/, '');
}

/** A formatting mark the toolbar adds. */
export type NoteMark = 'bold' | 'italic' | 'code' | 'list' | 'quote';

/**
 * `text` with `mark` put around the selection `[start, end)` (or, for a
 * line mark, at the start of each selected line), and the new selection.
 * Pure.
 */
export function applyMark(text: string, start: number, end: number, mark: NoteMark): { text: string; start: number; end: number } {
  if (mark === 'list' || mark === 'quote') {
    const prefix = mark === 'list' ? '- ' : '> ';
    const lineStart = text.lastIndexOf('\n', start - 1) + 1;
    const block = text.slice(lineStart, end);
    const marked = block.split('\n').map(l => (l.startsWith(prefix) ? l : prefix + l)).join('\n');
    return {
      text: text.slice(0, lineStart) + marked + text.slice(end),
      start: lineStart,
      end: lineStart + marked.length,
    };
  }
  const wrap = mark === 'bold' ? '**' : mark === 'italic' ? '_' : '`';
  const selected = text.slice(start, end);
  return {
    text: text.slice(0, start) + wrap + selected + wrap + text.slice(end),
    start: start + wrap.length,
    end: end + wrap.length,
  };
}

/** The files a drop or paste carries. Pure over the transfer. */
export function filesOf(transfer: DataTransfer | null | undefined): File[] {
  return transfer?.files?.length ? Array.from(transfer.files) : [];
}

/** Whether a file is shown as a thumbnail. Pure. */
export function isPreviewable(file: { type?: string; name: string }): boolean {
  return file.type ? file.type.startsWith('image/') : /\.(png|jpe?g|gif|webp|bmp)$/i.test(file.name);
}
