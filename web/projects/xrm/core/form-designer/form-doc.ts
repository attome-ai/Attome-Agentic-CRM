/**
 * A12-T3: a form document (`attome_model::kinds::form`) and the tree the
 * shared canvas edits. The canvas walks one children member, so the form's
 * tabs, sections, fields and related lists become one tree of typed nodes
 * (`form` > `tab` > `section` > `field` | `related`); labels and columns sit
 * in `props`, which the canvas's property panel edits. Saving turns the tree
 * back into the form's `tabs` or `sections`. All pure.
 */

/** A related list on a section. */
export interface RelatedDoc { entity: string; label?: string }

/** A form section (A12-T1). */
export interface SectionDoc {
  label: string;
  columns?: number;
  fields?: string[];
  related?: RelatedDoc[];
  components?: unknown[];
}

/** A form tab. */
export interface TabDoc { label: string; sections: SectionDoc[] }

/** A form document. */
export interface FormDoc {
  entity: string;
  form_kind?: string;
  sections?: SectionDoc[];
  tabs?: TabDoc[];
  targeting?: unknown;
}

export type DesignNodeType = 'form' | 'tab' | 'section' | 'field' | 'related';

/** One node of the canvas tree. */
export interface DesignNode {
  type: DesignNodeType;
  props?: Record<string, unknown>;
  /** A field's attribute id. */
  attribute?: string;
  /** A related list's entity id. */
  entity?: string;
  /** A section's embedded components, kept as they are. */
  components?: unknown[];
  children?: DesignNode[];
}

/** The canvas document: the tree under `/root`. */
export interface DesignDoc { root: DesignNode }

/** Most fields a form shows before it is flagged as slow. */
export const FIELD_BUDGET = 150;
/** Most related lists before it is flagged as slow. */
export const RELATED_BUDGET = 8;

function sectionNode(s: SectionDoc): DesignNode {
  const node: DesignNode = {
    type: 'section',
    props: { label: s.label ?? '', columns: s.columns ?? 1 },
    children: [
      ...(s.fields ?? []).map(attribute => ({ type: 'field' as const, attribute })),
      ...(s.related ?? []).map(r => ({ type: 'related' as const, entity: r.entity, props: { label: r.label ?? '' } })),
    ],
  };
  if (s.components?.length) node.components = s.components;
  return node;
}

/** The canvas tree of a form document. */
export function toDesign(doc: FormDoc): DesignDoc {
  const children = doc.tabs?.length
    ? doc.tabs.map(t => ({ type: 'tab' as const, props: { label: t.label ?? '' }, children: t.sections.map(sectionNode) }))
    : (doc.sections ?? []).map(sectionNode);
  return { root: { type: 'form', children } };
}

function text(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function columnsOf(value: unknown): number {
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 && n <= 4 ? n : 1;
}

function sectionDoc(node: DesignNode): SectionDoc {
  const fields: string[] = [];
  const related: RelatedDoc[] = [];
  for (const child of node.children ?? []) {
    if (child.type === 'field' && child.attribute) fields.push(child.attribute);
    if (child.type === 'related' && child.entity) {
      const label = text(child.props?.['label']).trim();
      related.push(label ? { entity: child.entity, label } : { entity: child.entity });
    }
  }
  const out: SectionDoc = { label: text(node.props?.['label']), fields };
  const columns = columnsOf(node.props?.['columns']);
  if (columns !== 1) out.columns = columns;
  if (related.length) out.related = related;
  if (node.components?.length) out.components = node.components;
  return out;
}

/**
 * The form document the tree describes, on `base` (its entity, kind and
 * targeting kept): `tabs` when the root holds tabs, else `sections`. A node
 * in the wrong place (a field outside a section, a tab inside one) is left
 * out and named in `misplaced`.
 */
export function fromDesign(design: DesignDoc, base: FormDoc): { doc: FormDoc; misplaced: number } {
  let misplaced = 0;
  const roots = design.root.children ?? [];
  const tabbed = roots.some(n => n.type === 'tab');
  const doc: FormDoc = { ...base };
  delete doc.tabs;
  delete doc.sections;
  if (tabbed) {
    doc.tabs = [];
    for (const node of roots) {
      if (node.type !== 'tab') { misplaced++; continue; }
      const sections: SectionDoc[] = [];
      for (const child of node.children ?? []) {
        if (child.type !== 'section') { misplaced++; continue; }
        misplaced += (child.children ?? []).filter(c => c.type !== 'field' && c.type !== 'related').length;
        sections.push(sectionDoc(child));
      }
      doc.tabs.push({ label: text(node.props?.['label']), sections });
    }
  } else {
    doc.sections = [];
    for (const node of roots) {
      if (node.type !== 'section') { misplaced++; continue; }
      misplaced += (node.children ?? []).filter(c => c.type !== 'field' && c.type !== 'related').length;
      doc.sections.push(sectionDoc(node));
    }
  }
  return { doc, misplaced };
}

/** Every section of a form document, tabbed or not. */
export function allSections(doc: FormDoc): SectionDoc[] {
  return doc.tabs?.length ? doc.tabs.flatMap(t => t.sections) : (doc.sections ?? []);
}

/** A problem the designer shows before publishing. */
export interface FormCheck {
  kind: 'accessibility' | 'performance' | 'layout';
  key: string;
  args?: Record<string, string | number>;
}

/**
 * The checks the designer shows: every tab and section labelled, every
 * field still an attribute of the entity, no field twice, nothing misplaced
 * (accessibility and layout); above 150 fields or 8 related lists, slow
 * (performance). `attributes` maps the entity's attribute ids to names.
 */
export function checkForm(
  doc: FormDoc,
  attributes: ReadonlyMap<string, string>,
  misplaced: number,
): FormCheck[] {
  const out: FormCheck[] = [];
  const sections = allSections(doc);
  (doc.tabs ?? []).forEach((t, i) => {
    if (!t.label.trim()) out.push({ kind: 'accessibility', key: 'tabLabel', args: { n: i + 1 } });
  });
  sections.forEach((s, i) => {
    if (!s.label.trim()) out.push({ kind: 'accessibility', key: 'sectionLabel', args: { n: i + 1 } });
  });
  const seen = new Set<string>();
  let fields = 0;
  let related = 0;
  for (const s of sections) {
    for (const f of s.fields ?? []) {
      fields++;
      if (!attributes.has(f)) out.push({ kind: 'accessibility', key: 'unknownField', args: { id: f } });
      if (seen.has(f)) out.push({ kind: 'layout', key: 'twice', args: { name: attributes.get(f) ?? f } });
      seen.add(f);
    }
    related += s.related?.length ?? 0;
  }
  if (misplaced) out.push({ kind: 'layout', key: 'misplaced', args: { count: misplaced } });
  if (fields > FIELD_BUDGET) out.push({ kind: 'performance', key: 'tooManyFields', args: { count: fields, budget: FIELD_BUDGET } });
  if (related > RELATED_BUDGET) out.push({ kind: 'performance', key: 'tooManyRelated', args: { count: related, budget: RELATED_BUDGET } });
  return out;
}

/** The field type number the renderer draws an attribute type with, for a preview. */
export function previewFieldType(type: string): number {
  switch (type) {
    case 'number': case 'integer': case 'decimal': case 'currency': case 'percent': return 1;
    case 'date': case 'date_time': return 5;
    case 'bool': return 6;
    case 'lookup': case 'file': case 'image': case 'formula': case 'multi_lookup': return 11;
    default: return 3;
  }
}
