import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';
import { ExpressionEditorComponent } from '@attome/xrm/core/admin/expression-editor';
import { TranslatePipe } from '@attome/base';
import {
  BusinessRuleOp, ConditionAll, ConditionAny, ConditionExpression, ConditionFieldKind, ConditionLeaf,
  ConditionTree, OPS_BY_KIND, isConditionAll, isConditionAny, isConditionExpression, isConditionLeaf,
  opTakesList, opTakesNoValue,
} from '@attome/xrm/core/admin/data';

/** Nesting of AND/OR groups, the root included (`MAX_TREE_DEPTH`). */
export const MAX_CONDITION_DEPTH = 4;

/** A field the condition builder offers (design section 2: the entity's own eligible fields). */
export interface ConditionEditorField {
  name: string;
  label: string;
  kind: ConditionFieldKind;
  /** Choice keys (choice and multi-choice fields). */
  choices: readonly string[];
  /** Translated labels of the choice keys, when the field has them. */
  choiceLabels?: Readonly<Record<string, string>> | null;
}

export type ConditionGroup = ConditionAll | ConditionAny;

/**
 * D-789 section 10 — one AND/OR group of the business-rule condition
 * builder: its leaves (field, operator by the field's type, a value input
 * per type), nested groups (recursively, up to `MAX_CONDITION_DEPTH`) and
 * "advanced expression" leaves. Stateless: every edit emits a new group
 * through `groupChange`; the editor owns the tree.
 */
@Component({
  selector: 'xrm-condition-group',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, ExpressionEditorComponent],
  styleUrls: ['./condition-group.component.css'],
  templateUrl: './condition-group.component.html',
})
export class ConditionGroupComponent {
  readonly group = input.required<ConditionGroup>();
  readonly fields = input.required<readonly ConditionEditorField[]>();
  /** Z11-T14: the entity an advanced expression reads, for its editor. */
  readonly entity = input('');
  /** 1 for the root group. */
  readonly depth = input(1);
  /** Path of this group in the body (`condition`, `condition.all[1]`), for issue matching. */
  readonly path = input('condition');
  /** Issue paths reported by `/validate` or a refused save. */
  readonly issuePaths = input<readonly string[]>([]);

  readonly groupChange = output<ConditionGroup>();
  /** A nested group asks its parent to drop it. */
  readonly removeGroup = output<void>();

  readonly mode = computed<'all' | 'any'>(() => isConditionAny(this.group()) ? 'any' : 'all');
  readonly children = computed<readonly ConditionTree[]>(() => {
    const g = this.group();
    return isConditionAny(g) ? g.any : (g as ConditionAll).all;
  });
  readonly isRoot = computed(() => this.depth() === 1);
  readonly canNest = computed(() => this.depth() < MAX_CONDITION_DEPTH);
  readonly groupId = computed(() => this.path().replace(/[^A-Za-z0-9_-]/g, '-'));

  // ── Node helpers for the template ─────────────────────────────────────────
  asLeaf(n: ConditionTree): ConditionLeaf | null { return isConditionLeaf(n) ? n : null; }
  asGroup(n: ConditionTree): ConditionGroup | null { return isConditionAll(n) || isConditionAny(n) ? n : null; }
  asExpression(n: ConditionTree): ConditionExpression | null {
    return !isConditionLeaf(n) && isConditionExpression(n) ? n : null;
  }

  childPath(i: number): string { return `${this.path()}.${this.mode()}[${i}]`; }

  hasIssue(path: string): boolean {
    return this.issuePaths().some(p => p === path || p.startsWith(`${path}.`));
  }

  fieldOf(name: string): ConditionEditorField | undefined {
    return this.fields().find(f => f.name === name);
  }

  opsFor(leaf: ConditionLeaf): readonly BusinessRuleOp[] {
    const f = this.fieldOf(leaf.field);
    return f ? OPS_BY_KIND[f.kind] : [];
  }

  takesNoValue(op: BusinessRuleOp): boolean { return opTakesNoValue(op); }

  /** A leaf whose value is a list: `in`/`not_in`, and `in` on a multi-choice. */
  takesList(leaf: ConditionLeaf): boolean { return opTakesList(leaf.op); }

  /** The value as an input shows it (a list one per line). */
  valueText(leaf: ConditionLeaf): string {
    const v = leaf.value;
    if (v === undefined || v === null) return '';
    if (Array.isArray(v)) return v.map(x => String(x)).join('\n');
    return String(v);
  }

  isListed(leaf: ConditionLeaf, key: string): boolean {
    return Array.isArray(leaf.value) && (leaf.value as unknown[]).includes(key);
  }

  choiceLabel(field: ConditionEditorField | undefined, key: string): string {
    return field?.choiceLabels?.[key] ?? key;
  }

  // ── Edits (each emits a new group) ────────────────────────────────────────
  setMode(mode: 'all' | 'any'): void {
    if (mode === this.mode()) return;
    const kids = [...this.children()];
    this.groupChange.emit(mode === 'any' ? { any: kids } : { all: kids });
  }

  addLeaf(): void {
    const f = this.fields()[0];
    if (!f) return;
    this.replaceChildren([...this.children(), this.newLeaf(f)]);
  }

  addGroup(): void {
    const f = this.fields()[0];
    if (!f || !this.canNest()) return;
    this.replaceChildren([...this.children(), { any: [this.newLeaf(f)] }]);
  }

  addExpression(): void {
    this.replaceChildren([...this.children(), { expression: '' }]);
  }

  removeChild(i: number): void {
    this.replaceChildren(this.children().filter((_, j) => j !== i));
  }

  updateChild(i: number, node: ConditionTree): void {
    this.replaceChildren(this.children().map((c, j) => j === i ? node : c));
  }

  setField(i: number, leaf: ConditionLeaf, name: string): void {
    const f = this.fieldOf(name);
    if (!f) return;
    this.updateChild(i, this.newLeaf(f, leaf.op));
  }

  setOp(i: number, leaf: ConditionLeaf, op: BusinessRuleOp): void {
    const next: ConditionLeaf = { field: leaf.field, op };
    // Keep a value whose shape still fits; otherwise start empty.
    if (!opTakesNoValue(op) && opTakesList(op) === opTakesList(leaf.op) && leaf.value !== undefined) {
      next.value = leaf.value;
    }
    this.updateChild(i, next);
  }

  /** A scalar value typed into the leaf's input. */
  setValue(i: number, leaf: ConditionLeaf, raw: string): void {
    const f = this.fieldOf(leaf.field);
    const value = f ? scalarFromInput(f.kind, raw) : raw;
    this.updateChild(i, withValue(leaf, value));
  }

  /** A list typed one value per line. */
  setListText(i: number, leaf: ConditionLeaf, raw: string): void {
    const f = this.fieldOf(leaf.field);
    const items = raw.split('\n').map(s => s.trim()).filter(s => s !== '');
    const value = items.length === 0 ? undefined : items.map(s => f ? scalarFromInput(f.kind, s) ?? s : s);
    this.updateChild(i, withValue(leaf, value));
  }

  /** A choice key ticked or unticked in a list leaf. */
  toggleListed(i: number, leaf: ConditionLeaf, key: string): void {
    const held = Array.isArray(leaf.value) ? [...(leaf.value as unknown[])] : [];
    const at = held.indexOf(key);
    if (at >= 0) held.splice(at, 1); else held.push(key);
    this.updateChild(i, withValue(leaf, held.length ? held : undefined));
  }

  setExpression(i: number, source: string): void {
    this.updateChild(i, { expression: source });
  }

  private replaceChildren(kids: ConditionTree[]): void {
    this.groupChange.emit(this.mode() === 'any' ? { any: kids } : { all: kids });
  }

  private newLeaf(f: ConditionEditorField, preferredOp?: BusinessRuleOp): ConditionLeaf {
    const ops = OPS_BY_KIND[f.kind];
    const op = preferredOp && ops.includes(preferredOp) ? preferredOp : ops[0];
    const leaf: ConditionLeaf = { field: f.name, op };
    if (f.kind === 'bool' && op === 'eq') leaf.value = true;
    return leaf;
  }
}

function withValue(leaf: ConditionLeaf, value: unknown): ConditionLeaf {
  const next: ConditionLeaf = { field: leaf.field, op: leaf.op };
  if (value !== undefined) next.value = value;
  return next;
}

/**
 * The typed JSON value of one input (design section 2's value column). A
 * number that does not parse is kept as typed so `/validate` names it
 * (`value_type`) instead of the editor silently dropping it.
 */
export function scalarFromInput(kind: ConditionFieldKind, raw: string): unknown {
  const s = raw.trim();
  if (s === '') return undefined;
  switch (kind) {
    case 'number': {
      const n = Number(s);
      return Number.isFinite(n) ? n : s;
    }
    case 'bool':
      return s === 'true' ? true : s === 'false' ? false : s;
    default:
      return s;
  }
}
