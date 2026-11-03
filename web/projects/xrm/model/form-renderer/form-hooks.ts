/**
 * A12-T4: a record form's extension hooks. The form asks the server to run
 * the entity's published extensions on its state (`POST
 * /api/v1/{entity}/form-hooks`); customer code never runs in the browser.
 */

/** A form event an extension can answer. */
export type FormHookEvent = 'load' | 'change' | 'before_save';

/** `POST /api/v1/{entity}/form-hooks`'s body. */
export interface FormHookRequest {
  event: FormHookEvent;
  record_id?: string | null;
  values: Record<string, unknown>;
  previous?: Record<string, unknown> | null;
}

/** What the extensions answered. */
export interface FormHookAnswer {
  /** Values to fill in. */
  changes: Record<string, unknown>;
  /** A refusal, in English. */
  rejection: string | null;
  /** The refusal in each language the extension wrote it in. */
  rejection_translations: Record<string, string>;
  /** The form events with an extension on this entity. */
  events: FormHookEvent[];
}

/** How long a typing pause is before `change` is sent. */
export const CHANGE_DEBOUNCE_MS = 400;

/**
 * The refusal in the person's language when the extension wrote one, else
 * its English text. Pure.
 */
export function rejectionText(answer: FormHookAnswer, lang: string): string | null {
  if (!answer.rejection) return null;
  return answer.rejection_translations[lang] ?? answer.rejection;
}

/** `values` with the extensions' changes filled in. Pure. */
export function withChanges(
  values: Readonly<Record<string, unknown>>,
  answer: FormHookAnswer,
): Record<string, unknown> {
  return Object.keys(answer.changes).length ? { ...values, ...answer.changes } : { ...values };
}
