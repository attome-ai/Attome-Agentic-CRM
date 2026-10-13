import {
  ChangeDetectionStrategy, Component, DestroyRef, ElementRef, OnDestroy, OnInit,
  afterNextRender, computed, inject, input, output, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { Observable } from 'rxjs';
import { LangService, TranslatePipe, pushModal, trapFocus } from '@attome/base';
import type { ApiError, ModalHandle } from '@attome/base';
import {
  CONVERSION_DATE_FORMATS, FieldChangeService, conversionTargets, structureErrorText,
  type AttributeMeta, type ConversionInput, type FieldChangeOutcome, type FieldChangeResult,
} from '@attome/xrm/core/admin/data';
import { FieldChangeResultComponent } from '../field-change-result/field-change-result.component';
import { FieldRunStatusComponent } from '../field-run-status/field-run-status.component';

export type FieldChangeMode = 'rename' | 'delete' | 'changeType' | 'choices';

/** `^[a-z][a-z0-9_]*$`, at most 63 (a PostgreSQL identifier), as the rename route checks. */
const FIELD_NAME = /^[a-z][a-z0-9_]{0,62}$/;

/** `text = value` lines → the text→choice map, or `null` when a line is malformed. */
export function parseChoiceMap(text: string): Record<string, string> | null {
  const map: Record<string, string> = {};
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const at = line.indexOf('=');
    if (at <= 0) return null;
    const from = line.slice(0, at).trim();
    const to = line.slice(at + 1).trim();
    if (!from || !to) return null;
    map[from] = to;
  }
  return map;
}

/** `"yes, Y ,true"` → `['yes', 'Y', 'true']`. */
export function splitList(text: string): string[] {
  return text.split(',').map(s => s.trim()).filter(s => s.length > 0);
}

/**
 * Solution 7 Phase 2 (D-788 rules 3–6; design §3.1–§3.5) — the field
 * structure changes of the metadata designer, one dialog per action:
 *
 * - **Rename**: the column and every reference follow; API callers using the
 *   old name break (said up front). "Check first" runs the dry run.
 * - **Delete**: the dry-run preview loads on open (blockers, objects that use
 *   the field, the values the recovery archive will keep); deleting needs an
 *   explicit tick.
 * - **Change type**: only the defined conversions are offered; the check
 *   shows how many values do not convert (they become empty and are kept in
 *   the archive).
 * - **Choices**: add a value (with its display name and place) or remove one
 *   (records keep it and show it empty; the check counts them).
 *
 * A large table answers with a background run (`FieldRunStatusComponent`,
 * with Abandon for a failed run). A blocked change is a `409` that still
 * carries its blockers, so they are shown, not just an error line. Closing
 * reports whether anything changed so the designer reloads.
 */
@Component({
  selector: 'attome-field-change-dialog',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, FieldChangeResultComponent, FieldRunStatusComponent],
  styleUrls: ['../../../../../styles/admin-page.css', './field-change-dialog.component.css'],
  templateUrl: './field-change-dialog.component.html',
  host: { '(document:keydown.escape)': 'onEscape()' },
})
export class FieldChangeDialogComponent implements OnInit, OnDestroy {
  private readonly svc = inject(FieldChangeService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);

  readonly entityId = input.required<string>();
  readonly field = input.required<AttributeMeta>();
  readonly mode = input.required<FieldChangeMode>();
  /** `true` when a change was applied (the designer reloads the entity). */
  readonly closed = output<boolean>();

  readonly dateFormats = CONVERSION_DATE_FORMATS;

  readonly busy = signal<'check' | 'apply' | null>(null);
  readonly error = signal<string | null>(null);
  readonly result = signal<FieldChangeResult | null>(null);
  readonly approvalId = signal<string | null>(null);
  readonly changed = signal(false);

  // Rename
  readonly newName = signal('');
  // Delete
  readonly deleteConfirmed = signal(false);
  // Change type
  readonly targetType = signal('');
  readonly dateFormat = signal<string>('iso8601');
  readonly trueValues = signal('');
  readonly falseValues = signal('');
  readonly mapText = signal('');
  // Choices
  readonly choices = signal<string[]>([]);
  readonly newChoiceValue = signal('');
  readonly newChoiceLabel = signal('');
  readonly newChoiceAfter = signal('');
  readonly removeValue = signal('');

  private modal: ModalHandle | null = null;
  private releaseTrap: (() => void) | null = null;

  readonly titleKey = computed(() => ({
    rename: 'fieldChange.dialog.titleRename',
    delete: 'fieldChange.dialog.titleDelete',
    changeType: 'fieldChange.dialog.titleChangeType',
    choices: 'fieldChange.dialog.titleChoices',
  })[this.mode()]);

  /** The catalog key of what is wrong with the typed name, or `null`. */
  readonly renameIssue = computed(() => {
    const name = this.newName().trim().toLowerCase();
    if (!FIELD_NAME.test(name)) return 'fieldChange.rename.invalid';
    if (name === this.field().logicalname) return 'fieldChange.rename.same';
    return null;
  });

  /** The delete preview loaded and nothing blocks it. */
  readonly deleteReady = computed(() => {
    const r = this.result();
    return r !== null && r.op === 'delete_field' && r.dry_run && !r.error;
  });

  readonly targets = computed(() => conversionTargets(this.field().field_type));
  readonly needsFormat = computed(() => {
    const from = this.field().field_type;
    const to = this.targetType();
    return (from === 'text' && to === 'date') || (from === 'date' && to === 'text');
  });
  readonly needsBoolValues = computed(() => this.field().field_type === 'text' && this.targetType() === 'bool');
  readonly needsMap = computed(() => this.field().field_type === 'text' && this.targetType() === 'choice');
  /** The catalog key of what is wrong with the conversion inputs, or `null`. */
  readonly conversionIssue = computed(() => {
    if (!this.targetType()) return 'fieldChange.changeType.choose';
    if (this.needsMap()) {
      const map = parseChoiceMap(this.mapText());
      if (map === null) return 'fieldChange.changeType.mapInvalid';
      if (Object.keys(map).length === 0) return 'fieldChange.changeType.mapRequired';
    }
    return null;
  });

  readonly isChoiceField = computed(() => this.field().field_type === 'choice');
  readonly addChoiceIssue = computed(() =>
    this.newChoiceValue().trim() && this.newChoiceLabel().trim() ? null : 'fieldChange.choices.required');

  /** The background run a real (not dry-run) change started. */
  readonly runId = computed(() => {
    const r = this.result();
    return r && !r.dry_run && r.run_id ? r.run_id : null;
  });

  constructor() {
    afterNextRender(() => {
      const dialog = this.host.nativeElement.querySelector<HTMLElement>('.fcd-dialog');
      if (!dialog) return;
      this.modal = pushModal();
      this.releaseTrap = trapFocus(dialog);
      dialog.querySelector<HTMLElement>('[data-autofocus]')?.focus();
    });
  }

  ngOnInit(): void {
    const f = this.field();
    this.newName.set(f.logicalname);
    const raw: unknown = (f.options as { choices?: unknown } | null | undefined)?.choices;
    this.choices.set(Array.isArray(raw) ? raw.filter((c): c is string => typeof c === 'string') : []);
    this.removeValue.set(this.choices()[0] ?? '');
    if (this.mode() === 'delete') this.checkDelete();
  }

  ngOnDestroy(): void {
    this.releaseTrap?.();
    this.modal?.release();
  }

  onEscape(): void {
    if (this.modal && !this.modal.isTop()) return;
    this.close();
  }

  close(): void {
    this.closed.emit(this.changed());
  }

  typeKey(t: string): string { return `fieldTypes.${t}`; }

  // ── Rename ──────────────────────────────────────────────────────────────

  checkRename(): void {
    if (this.renameIssue()) return;
    this.run('check', this.svc.rename(this.entityId(), this.field().id, this.newName().trim().toLowerCase(), true));
  }

  applyRename(): void {
    if (this.renameIssue()) return;
    this.run('apply', this.svc.rename(this.entityId(), this.field().id, this.newName().trim().toLowerCase(), false));
  }

  // ── Delete ──────────────────────────────────────────────────────────────

  checkDelete(): void {
    this.deleteConfirmed.set(false);
    this.run('check', this.svc.delete(this.entityId(), this.field().id, true));
  }

  applyDelete(): void {
    if (!this.deleteReady() || !this.deleteConfirmed()) return;
    this.run('apply', this.svc.delete(this.entityId(), this.field().id, false));
  }

  // ── Change type ─────────────────────────────────────────────────────────

  private conversion(): ConversionInput {
    const c: ConversionInput = { from_type: this.field().field_type };
    if (this.needsFormat()) c.format = this.dateFormat();
    if (this.needsBoolValues()) {
      const t = splitList(this.trueValues());
      const f = splitList(this.falseValues());
      if (t.length > 0) c.true_values = t;
      if (f.length > 0) c.false_values = f;
    }
    if (this.needsMap()) c.map = parseChoiceMap(this.mapText()) ?? {};
    return c;
  }

  checkChangeType(): void {
    if (this.conversionIssue()) return;
    this.run('check', this.svc.changeType(this.entityId(), this.field().id, this.targetType(), this.conversion(), true));
  }

  applyChangeType(): void {
    if (this.conversionIssue()) return;
    this.run('apply', this.svc.changeType(this.entityId(), this.field().id, this.targetType(), this.conversion(), false));
  }

  // ── Choices ─────────────────────────────────────────────────────────────

  addChoice(): void {
    if (this.addChoiceIssue()) return;
    const value = this.newChoiceValue().trim();
    const after = this.newChoiceAfter();
    this.run('apply', this.svc.addChoice(this.entityId(), this.field().id, {
      value, label: this.newChoiceLabel().trim(), after: after || undefined,
      // The display name is typed in the UI language; store it as that label.
      locale: this.lang.current(),
    }), () => {
      this.choices.update(list => {
        if (list.includes(value)) return list;
        const at = after ? list.indexOf(after) : -1;
        return at >= 0 ? [...list.slice(0, at + 1), value, ...list.slice(at + 1)] : [...list, value];
      });
      this.newChoiceValue.set('');
      this.newChoiceLabel.set('');
    });
  }

  checkRemoveChoice(): void {
    const value = this.removeValue();
    if (!value) return;
    this.run('check', this.svc.removeChoice(this.entityId(), this.field().id, value, true));
  }

  removeChoice(): void {
    const value = this.removeValue();
    if (!value) return;
    this.run('apply', this.svc.removeChoice(this.entityId(), this.field().id, value, false), () => {
      this.choices.update(list => list.filter(c => c !== value));
      this.removeValue.set(this.choices()[0] ?? '');
    });
  }

  /** The run was abandoned: the field is free again; the designer should reload. */
  onRunAbandoned(): void {
    this.changed.set(true);
  }

  private run(kind: 'check' | 'apply', call$: Observable<FieldChangeOutcome>, onApplied?: () => void): void {
    if (this.busy()) return;
    this.busy.set(kind);
    this.error.set(null);
    this.approvalId.set(null);
    call$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: outcome => {
        this.busy.set(null);
        if (outcome.kind === 'approval') {
          this.result.set(null);
          this.approvalId.set(outcome.approvalRequestId);
          return;
        }
        this.result.set(outcome.result);
        if (!outcome.result.dry_run && outcome.result.applied && !outcome.result.error) {
          this.changed.set(true);
          onApplied?.();
        }
      },
      error: (err: ApiError) => {
        this.busy.set(null);
        this.error.set(structureErrorText(this.lang, err));
      },
    });
  }
}
