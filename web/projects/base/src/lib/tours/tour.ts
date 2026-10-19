/**
 * B14-T1: guided tours. A tour is a metadata object (`tour` kind) the
 * server filters by role and serves at `GET /api/v1/model/tours`; each step
 * points at one element with a CSS selector and carries English and/or
 * Arabic text.
 */

/** A text in English, Arabic or both. */
export interface LocalText {
  en?: string;
  ar?: string;
}

/** Where a step's bubble sits beside its element. */
export type TourPlacement = 'top' | 'bottom' | 'start' | 'end';

export interface TourStep {
  selector: string;
  title?: LocalText;
  text: LocalText;
  placement?: TourPlacement;
}

/** `attome_api::model_admin::TourView`. */
export interface Tour {
  id: string;
  name: string;
  title: LocalText;
  /** The app path prefix the tour belongs to. */
  route: string;
  /** Starts by itself the first time the person opens `route`. */
  auto_start: boolean;
  steps: TourStep[];
}

/** The setting that keeps the tours a person finished or skipped. */
export const TOURS_SEEN_SETTING = 'core.tours_seen';

/** `text` in `lang`, falling back to the other language, else ''. */
export function localText(text: LocalText | undefined, lang: string): string {
  if (!text) return '';
  return (lang === 'ar' ? text.ar || text.en : text.en || text.ar) ?? '';
}

/** Whether `url` (with or without a query) is on `route` or below it. */
export function routeMatches(route: string, url: string): boolean {
  const path = url.split(/[?#]/)[0].replace(/\/+$/, '') || '/';
  const base = route.replace(/\/+$/, '') || '/';
  return base === '/' || path === base || path.startsWith(base + '/');
}

/** The tour for `url`: the one with the longest matching route. */
export function tourFor(tours: readonly Tour[], url: string): Tour | null {
  return tours
    .filter(t => t.steps.length > 0 && routeMatches(t.route, url))
    .sort((a, b) => b.route.length - a.route.length)[0] ?? null;
}

/** The tour to start by itself on `url`: a starting tour not yet seen. */
export function autoTour(tours: readonly Tour[], url: string, seen: readonly string[]): Tour | null {
  const tour = tourFor(tours.filter(t => t.auto_start && !seen.includes(t.id)), url);
  return tour;
}
