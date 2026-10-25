/** E13-T12: how long a text looks, in what a reader counts as characters
 *  (a combining Arabic mark is not a character of its own). */
export function displayLength(text: string | null | undefined): number {
  if (!text) return 0;
  return Array.from(text.normalize('NFC')).filter(c => !/\p{Mn}/u.test(c)).length;
}

export type LengthState = 'empty' | 'short' | 'ok' | 'long';

/** Whether a length sits in its band: titles 30–60, descriptions 70–160. */
export function lengthState(length: number, min: number, max: number): LengthState {
  if (length === 0) return 'empty';
  if (length < min) return 'short';
  if (length > max) return 'long';
  return 'ok';
}

export const TITLE_BAND = { min: 30, max: 60 } as const;
export const DESCRIPTION_BAND = { min: 70, max: 160 } as const;

/** Whether a text is written in Arabic script (its preview reads right to left). */
export function isArabic(text: string | null | undefined): boolean {
  return /[؀-ۿݐ-ݿ]/.test(text ?? '');
}

/** What a search result would show: the text cut at `max` display characters. */
export function clip(text: string | null | undefined, max: number): string {
  const chars = Array.from(text ?? '');
  return chars.length > max ? `${chars.slice(0, max - 1).join('')}…` : chars.join('');
}

/** Lines added and removed going from `before` to `after`, as sets of lines. */
export function lineChanges(before: string, after: string): { added: number; removed: number } {
  const a = before.split('\n').map(l => l.trimEnd()).filter(Boolean);
  const b = after.split('\n').map(l => l.trimEnd()).filter(Boolean);
  const inA = new Set(a);
  const inB = new Set(b);
  return {
    added: b.filter(l => !inA.has(l)).length,
    removed: a.filter(l => !inB.has(l)).length,
  };
}
