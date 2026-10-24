import type { MasterField, MasterProvenance } from '@attome/xrm/core/admin/data';

/** One line of the golden record panel: an attribute, or an English and Arabic pair. */
export interface GoldenRow {
  attribute: string;
  label: string;
  value: unknown;
  provenance: MasterProvenance;
  /** The `<attribute>_ar` twin, shown beside the English value. */
  arabic?: { attribute: string; value: unknown; provenance: MasterProvenance };
}

/**
 * L1-T9: the panel's lines, in the provenance order (by attribute). An
 * attribute and its `_ar` twin become one line, so a legal name reads as a
 * pair; an `_ar` attribute without an English twin stands alone. Only
 * attributes with provenance appear: the others are not chosen from sources.
 */
export function goldenRows(
  fields: readonly MasterField[],
  values: Readonly<Record<string, unknown>>,
  provenance: readonly MasterProvenance[],
): GoldenRow[] {
  const label = new Map(fields.map(f => [f.name, f.display_name || f.name]));
  const byName = new Map(provenance.map(p => [p.attribute, p]));
  const rows: GoldenRow[] = [];
  for (const p of provenance) {
    const twinOf = p.attribute.endsWith('_ar') ? p.attribute.slice(0, -3) : null;
    if (twinOf && byName.has(twinOf)) {
      continue;
    }
    const row: GoldenRow = {
      attribute: p.attribute,
      label: label.get(p.attribute) ?? p.attribute,
      value: values[p.attribute],
      provenance: p,
    };
    const twin = byName.get(`${p.attribute}_ar`);
    if (twin) {
      row.arabic = { attribute: twin.attribute, value: values[twin.attribute], provenance: twin };
    }
    rows.push(row);
  }
  return rows;
}

/** A value as the panel prints it. */
export function shown(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
