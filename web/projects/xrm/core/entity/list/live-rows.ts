import type { LiveRecords } from '@attome/base';

/** What one live frame means for a list of `entity` showing `shown`. */
export interface LiveRowsEffect {
  /** Records created that the list does not show yet. */
  created: number;
  /** A shown record changed, was deleted or restored: reload the page. */
  reload: boolean;
  /** Too many changes to list: offer a reload. */
  overflow: boolean;
}

/** A13-T4: reads one `records` frame for a list. */
export function liveRows(entity: string, frame: LiveRecords, shown: ReadonlySet<string>): LiveRowsEffect {
  if ('overflow' in frame) return { created: 0, reload: false, overflow: true };
  const mine = frame.changes.filter(c => c.entity === entity);
  return {
    created: mine.filter(c => c.op === 'create' && !shown.has(c.id)).length,
    reload: mine.some(c => c.op !== 'create' && shown.has(c.id)),
    overflow: false,
  };
}
