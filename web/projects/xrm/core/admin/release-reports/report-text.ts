import type { LangService } from '@attome/base';
import type { ReportItem } from '@attome/xrm/core/admin/data';

type Translate = Pick<LangService, 'translate'>;

function str(value: unknown): string | null {
  if (typeof value === 'string' && value.length > 0) return value;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return null;
}

/** The first count a kind's `detail` carries (`archived`, `nulled`, `records`, ...). */
function detailCount(detail: Record<string, unknown>): string | null {
  for (const key of ['archived', 'nulled', 'records', 'rows', 'count', 'empty']) {
    const v = str(detail[key]);
    if (v !== null) return v;
  }
  return null;
}

/**
 * One plain sentence that says what happened, built from the item's kind and
 * its `detail` (counts and names only — `detail` never carries record
 * values). A `detail` key the release did not write falls back to a neutral
 * word, never to a raw key.
 */
export function describeItem(lang: Translate, item: Pick<ReportItem, 'kind' | 'entity_logicalname' | 'field_logicalname' | 'object_kind' | 'detail'>): string {
  const d = (item.detail && typeof item.detail === 'object' ? item.detail : {}) as Record<string, unknown>;
  const some = lang.translate('releaseReport.text.unknownCount');
  const params: Record<string, unknown> = {
    entity: item.entity_logicalname,
    field:  item.field_logicalname ?? lang.translate('releaseReport.text.noField'),
    from:   str(d['from']) ?? '?',
    to:     str(d['to']) ?? '?',
    count:  detailCount(d) ?? some,
    value:  str(d['value']) ?? '?',
    object: item.object_kind ?? '?',
    name:   str(d['name']) ?? str(d['rule']) ?? '?',
    change: str(d['change']) ?? '?',
  };
  // A business-rule conflict names no field (`detail.rule` names the rule).
  if (item.kind === 'conflict' && !item.field_logicalname) {
    return lang.translate('releaseReport.text.conflict_rule', params);
  }
  switch (item.kind) {
    case 'conflict':
    case 'conversion_nulled':
    case 'field_deleted':
    case 'customer_object_adjusted':
    case 'customer_object_removed':
    case 'choice_removed_in_use':
    case 'required_empty':
      return lang.translate(`releaseReport.text.${item.kind}`, params);
    case 'customisation_affected':
      return lang.translate(
        str(d['change']) === 'renamed'
          ? 'releaseReport.text.customisation_renamed'
          : 'releaseReport.text.customisation_removed',
        params,
      );
    case 'breaking_api_change': {
      const change = str(d['change']);
      const variant = change === 'renamed' || change === 'removed' || change === 'type' ? change : 'other';
      return lang.translate(`releaseReport.text.breaking_${variant}`, params);
    }
    default:
      return lang.translate('releaseReport.text.unknown', params);
  }
}

/** A conflict value as text: empty → the catalog's "(empty)", a string as is, anything else as JSON. */
export function formatValue(lang: Translate, value: unknown): string {
  if (value === null || value === undefined || value === '') return lang.translate('releaseReport.item.empty');
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
