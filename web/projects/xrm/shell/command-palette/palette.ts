import { Injectable, signal } from '@angular/core';

/** What a palette query asks for. */
export type PaletteScope = 'all' | 'commands' | 'records';

export interface PaletteQuery {
  scope: PaletteScope;
  /** For `acc: acme`, `acc`: only records of entities whose name starts so. */
  entityPrefix: string | null;
  /** The text to match, without the prefix. */
  text: string;
}

/**
 * B10-T1: reads a palette query. `>` lists commands only; `acc:` (any word
 * followed by a colon) searches records of the entities that word starts;
 * anything else searches records, pages and commands together.
 */
export function parsePaletteQuery(raw: string): PaletteQuery {
  const q = raw.trimStart();
  if (q.startsWith('>')) return { scope: 'commands', entityPrefix: null, text: q.slice(1).trim() };
  const scoped = /^([a-z][a-z0-9_]{1,40}):\s*(.*)$/i.exec(q);
  if (scoped) return { scope: 'records', entityPrefix: scoped[1].toLowerCase(), text: scoped[2].trim() };
  return { scope: 'all', entityPrefix: null, text: q.trim() };
}

/**
 * B10-T3: whether palette text reads as a question for the copilot rather
 * than a name to find: it ends with a question mark (Latin or Arabic) or
 * runs to three words or more.
 */
export function isQuestion(text: string): boolean {
  const t = text.trim();
  if (!t) return false;
  if (/[?؟]$/.test(t)) return true;
  return t.split(/\s+/).length >= 3;
}

/** True when the entity's name, or one of its `_` parts, starts with the prefix. */
export function entityMatchesPrefix(entity: string, prefix: string): boolean {
  const name = entity.toLowerCase();
  return name.startsWith(prefix) || name.split('_').some(part => part.startsWith(prefix));
}

/**
 * Orders palette items: the open page's own commands first, then the ones
 * this person uses most, otherwise as given.
 */
export function rankByUse<T extends { id: string; context?: boolean }>(
  items: readonly T[],
  uses: (id: string) => number,
): T[] {
  return items
    .map((item, index) => ({ item, index, uses: uses(item.id), context: item.context ? 1 : 0 }))
    .sort((a, b) => (b.context - a.context) || (b.uses - a.uses) || (a.index - b.index))
    .map(entry => entry.item);
}

const STORAGE_KEY = 'attome.palette.uses';
/** Items whose use counts are kept; the least used are dropped beyond it. */
const MAX_KEPT = 200;

/**
 * How often this person picked each palette item, kept in this browser.
 * Losing it (a private window, cleared site data) only loses the ordering.
 */
@Injectable({ providedIn: 'root' })
export class PaletteUses {
  private readonly counts = signal<Record<string, number>>(readCounts());

  count(id: string): number {
    return this.counts()[id] ?? 0;
  }

  bump(id: string): void {
    const next = { ...this.counts(), [id]: (this.counts()[id] ?? 0) + 1 };
    const ids = Object.keys(next);
    if (ids.length > MAX_KEPT) {
      ids.sort((a, b) => next[a] - next[b]);
      for (const drop of ids.slice(0, ids.length - MAX_KEPT)) delete next[drop];
    }
    this.counts.set(next);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // Storage unavailable: the ordering lasts for this page only.
    }
  }
}

function readCounts(): Record<string, number> {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}');
    if (!parsed || typeof parsed !== 'object') return {};
    const out: Record<string, number> = {};
    for (const [id, n] of Object.entries(parsed)) if (typeof n === 'number' && n > 0) out[id] = n;
    return out;
  } catch {
    return {};
  }
}
