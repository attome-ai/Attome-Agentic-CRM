import type { ApiError, LangService } from '@attome/base';
import { stableErrorCode } from './admin-http';

/**
 * The user-facing text of a failed release-report, recovery-archive or
 * field-change call: the catalog's `structureErrors.<code>` when the failure
 * carries one of the stable codes, else `LangService.errorText` (which shows
 * a validation message as the server wrote it, and every other kind from the
 * catalog).
 */
export function structureErrorText(
  lang: Pick<LangService, 'translate' | 'errorText'>,
  err: Pick<ApiError, 'kind' | 'code' | 'message'> | null | undefined,
): string {
  const code = stableErrorCode(err);
  if (code) {
    const key = `structureErrors.${code}`;
    const text = lang.translate(key);
    if (text !== key) return text;
  }
  return lang.errorText(err);
}
