import {
  ChangeDetectionStrategy, Component, ElementRef, OnDestroy, OnInit,
  computed, inject, input, signal, viewChild,
} from '@angular/core';
import {
  AbstractControl, ControlContainer, FormGroup,
  FormGroupDirective, ReactiveFormsModule,
} from '@angular/forms';
import { Subscription } from 'rxjs';
import { ScanService } from '@attome/base/scan';

import {
  CurrencyService, HijriParts, LangService, TranslatePipe, UserPreferencesService,
  fromHijri, hijriMonthName, toHijri,
} from '@attome/base';
import {
  ChoiceOptions, DateOptions, FieldSchema, FileOptions, FormulaOptions, LookupOptions, TextOptions,
} from '@attome/xrm';
import { XRM_FIELD_POLICY, isEmptyFieldValue } from '../../business-rules/field-policy';
import { EntityService } from '../../services/entity.service';
import { FileUploadService, RestoreVersionResponse } from '../file-upload.service';
import { FileVersionsComponent } from '../file-versions/file-versions.component';
import { UploadPipeline } from '../upload-pipeline';
import { MultiAttachmentComponent } from '../multi-attachment/multi-attachment.component';
import { RichTextEditorComponent } from '../rich-text-editor/rich-text-editor.component';
import { FieldHistoryComponent } from '../field-history/field-history.component';
import { ImageUploadComponent } from '../image-upload/image-upload.component';
import { ScanFieldOptions, scanToValues } from './scan-to-values';
import { checkFailure } from '../field-checks';

/** Y2-T1: a stored moment as a `datetime-local` value in the viewer's zone;
 *  empty for none or one that does not parse. */
export function toLocalDateTimeInput(value: unknown): string {
  if (typeof value !== 'string' || !value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Y2-T1: a `datetime-local` value (the viewer's zone) as the moment to
 *  store; `null` for an empty input, `undefined` for one that does not parse. */
export function fromLocalDateTimeInput(raw: string): string | null | undefined {
  if (!raw) return null;
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

@Component({
  selector: 'attome-field-input',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    ReactiveFormsModule, TranslatePipe, MultiAttachmentComponent, FileVersionsComponent,
    RichTextEditorComponent, ImageUploadComponent, FieldHistoryComponent,
  ],
  viewProviders: [{ provide: ControlContainer, useExisting: FormGroupDirective }],
  // The grid item is this host element, not the .xf-field inside it, so the
  // full-width class has to land here for `grid-column: 1 / -1` to take.
  host: {
    '[class.xf-field-wide]':          'isWideField()',
    // D-789 section 5: a field a business rule hides takes no grid cell.
    '[style.display]':                "policyHidden() ? 'none' : null",
    '(document:keydown.escape)':      'onEscape()',
  },
  // Shares the form design language with the rest of the platform's forms, so
  // a generic metadata-driven field looks the same as a hand-written one.
  styleUrls: ['../../../../styles/xrm-form.css', './field-input.component.css'],
  templateUrl: './field-input.component.html',
})
export class FieldInputComponent implements OnInit, OnDestroy {
  readonly field      = input.required<FieldSchema>();
  // Only needed for the 'file' case (the upload-session routes are scoped to
  // an existing record) — other field types ignore these.
  readonly entityName = input<string | null>(null);
  readonly recordId   = input<string | null>(null);

  private readonly searchInputRef = viewChild<ElementRef<HTMLInputElement>>('searchInput');
  private readonly scanVideoRef = viewChild<ElementRef<HTMLVideoElement>>('scanVideo');

  private readonly cc       = inject(ControlContainer);
  private readonly svc      = inject(EntityService);
  private readonly fileSvc  = inject(FileUploadService);
  private readonly currency = inject(CurrencyService);
  private readonly lang     = inject(LangService);
  private readonly prefs    = inject(UserPreferencesService);
  private readonly scanner  = inject(ScanService);

  // ── Scanning (B16-T4) ─────────────────────────────────────────────────────
  /** The field's `options.scan`, when it has one. */
  readonly scanOpts = computed(() =>
    ((this.field().options as { scan?: ScanFieldOptions } | null)?.scan) ?? null);
  /** A scan button shows for a text or number field whose scan setting is on. */
  readonly canScan = computed(() => {
    const scan = this.scanOpts();
    return !!scan && scan.enabled !== false && ['text', 'number'].includes(this.field().field_type);
  });
  readonly scanOpen  = signal(false);
  readonly scanError = signal<string | null>(null);
  private scanSub: Subscription | null = null;

  /** Opens the camera under the field; the first code read fills it. */
  openScan(): void {
    this.scanError.set(null);
    this.scanOpen.set(true);
    // The <video> renders with the panel; start once it exists.
    queueMicrotask(() => {
      const video = this.scanVideoRef()?.nativeElement;
      if (!video) return;
      this.scanSub = this.scanner.startCamera(video, { continuous: false }).subscribe({
        next: r => this.applyScan(r.rawValue, r.format),
        error: () => { this.scanError.set('fieldInput.scan.cameraDenied'); this.closeScan(); },
      });
    });
  }

  closeScan(): void {
    this.scanSub?.unsubscribe();
    this.scanSub = null;
    this.scanner.stop();
    this.scanOpen.set(false);
  }

  /** Puts one scan into the form: the value, and GS1 batch and expiry into their fields. */
  applyScan(raw: string, format: string): void {
    const fill = scanToValues(raw, format, this.field().field_type, this.scanOpts());
    this.closeScan();
    if (fill.error) {
      this.scanError.set(fill.error);
      return;
    }
    this.scanError.set(null);
    const value = this.field().field_type === 'number' ? Number(fill.value) : fill.value;
    this.ctrl.setValue(value);
    this.ctrl.markAsDirty();
    const form = this.cc.control as FormGroup;
    for (const [name, v] of Object.entries(fill.siblings)) {
      const sibling = form.get(name);
      if (!sibling) continue;
      sibling.setValue(v);
      sibling.markAsDirty();
    }
  }

  // ── Hijri entry (AG1-T8) ──────────────────────────────────────────────────
  /** Hijri day, month and year inputs beside a date field, when the field's
   *  own option or the person's calendar setting asks for Hijri. */
  readonly hijriEntry = computed(() => {
    if (this.field().field_type !== 'date') return false;
    const own = (this.field().options as DateOptions | null)?.display_calendar;
    const calendar = own ?? this.prefs.calendar();
    return calendar === 'hijri' || calendar === 'both';
  });
  readonly hijriMonths = Array.from({ length: 12 }, (_, i) => i + 1);

  /** B2-T3: fields whose past values the history popover can put back. */
  readonly hasHistory = computed(() =>
    !!this.recordId() && !!this.entityName()
    && !['file', 'image', 'formula'].includes(this.field().field_type));

  /** Puts a past value back into the control; saving the form writes it. */
  restoreValue(value: unknown): void {
    this.ctrl.setValue(value);
    this.ctrl.markAsDirty();
  }

  /** Y2-T1: the control's moment for the `datetime-local` input. */
  localDateTime(): string {
    return toLocalDateTimeInput(this.ctrl.value);
  }

  /** Y2-T1: writes the moment the `datetime-local` input holds. */
  setDateTime(raw: string): void {
    const value = fromLocalDateTimeInput(raw);
    if (value === undefined) return;
    this.ctrl.setValue(value);
    this.ctrl.markAsDirty();
  }

  /** The Hijri date the control holds, if any. */
  hijriValue(): HijriParts | null {
    const value: unknown = this.ctrl.value;
    return typeof value === 'string' && value ? toHijri(value) : null;
  }

  hijriMonthName(month: number): string {
    return hijriMonthName(month, this.lang.current());
  }

  /** Writes the control from one changed Hijri part; a 30th that does not
   *  exist in that month becomes the 29th. */
  setHijriPart(part: keyof HijriParts, raw: string): void {
    const value = Number(raw);
    if (!Number.isInteger(value)) return;
    const today = toHijri(new Date().toISOString().slice(0, 10));
    const current = this.hijriValue() ?? today ?? { year: 1447, month: 1, day: 1 };
    const next = { ...current, [part]: value };
    const iso = fromHijri(next) ?? fromHijri({ ...next, day: Math.min(next.day, 29) });
    if (!iso) return;
    this.ctrl.setValue(iso);
    this.ctrl.markAsDirty();
  }

  // ── Business-rule policy (D-789 section 5) ────────────────────────────────
  // Provided by the enclosing `<xrm-base-form>`; absent outside one, where
  // the field behaves as before. Presentation only: the server refuses a
  // write that changes a locked field.
  private readonly policy = inject(XRM_FIELD_POLICY, { optional: true });

  /** The lock a business rule puts on this field for the signed-in user. */
  readonly lock = computed(() => this.policy?.lock(this.field().name) ?? null);
  /** `hidden`: render nothing (not shown, not editable). */
  readonly policyHidden = computed(() => this.lock()?.effect === 'hidden');
  /** `disabled`: render read-only with a lock naming the rule. A formula is read-only anyway. */
  readonly policyDisabled = computed(() =>
    this.lock()?.effect === 'disabled' && this.field().field_type !== 'formula');
  /** Field-attached `error` policies firing on the current values (live, never blocking). */
  readonly ruleMessages = computed(() => this.policy?.ruleErrors(this.field().name) ?? []);
  /** The last save's refusal naming this field. */
  readonly serverError = computed(() => this.policy?.serverError(this.field().name) ?? null);
  /** Required, locked and empty: the save will be refused (section 3.4). */
  readonly requiredLocked = computed(() => this.policy?.requiredLocked(this.field().name) ?? false);

  /** Element id of the lock note, referenced by the read-only value. */
  lockNoteId(): string { return `${this.field().name}-lock`; }

  /** The read-only rendering of a locked field's value. */
  readonly lockedDisplay = computed(() => {
    const f = this.field();
    const v = this.policy?.value(f.name);
    if (isEmptyFieldValue(v)) return this.lang.translate('fieldPolicy.noValue');
    switch (f.field_type) {
      case 'bool':
        return this.lang.translate(v === true ? 'fieldInput.formulaTrue' : 'fieldInput.formulaFalse');
      case 'choice':
        return Array.isArray(v) ? v.map(c => this.choiceLabel(String(c))).join(', ') : this.choiceLabel(String(v));
      case 'lookup':
        return this.lookupLabel() || String(v);
      case 'currency': {
        const n = Number(v);
        if (!Number.isFinite(n)) return String(v);
        const shown = Math.round(this.currency.fromBase(n, this.preferredCurrency()) * 100) / 100;
        return `${shown.toLocaleString()} ${this.preferredCurrency()}`;
      }
      case 'number': {
        const n = Number(v);
        return Number.isFinite(n) ? n.toLocaleString() : String(v);
      }
      case 'file':
      case 'image': {
        if (Array.isArray(v)) return this.lang.translate('fieldPolicy.fileCount', { count: v.length });
        const key = String(v);
        const last = key.split('/').pop() ?? key;
        return last.length > 37 ? last.slice(37) : last;
      }
      case 'rich_text':
        // Shown as plain text: the stored HTML is never rendered unsanitised.
        return String(v).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
      default:
        return String(v);
    }
  });

  // ── Formula state (U9, D-604) ─────────────────────────────────────────────
  // A formula's control is disabled (`EngineFormBase.buildFormGroup`), so it is
  // never submitted; its value is mirrored into a signal for the same OnPush
  // reason `currencyCtrlValue` is.
  private readonly formulaCtrlValue = signal<unknown>(null);
  private formulaCtrlValueSub?: Subscription;

  // ── Currency state (D-490) ────────────────────────────────────────────────
  // Every `currency` field stores/validates as a plain USD amount; the
  // displayed amount is converted for the viewer's preferred currency,
  // entirely client-side. `preferredCurrency`/`currencyRatesList` are the
  // service's own signals — a template method reading a signal
  // establishes the same reactive dependency a direct template binding would
  // (Angular's OnPush + signals integration), so no manual `markForCheck` is
  // needed when the viewer switches currency. `currencyCtrlValue` mirrors
  // `fileCtrlValue`'s pattern above for the same reason: reactive-forms
  // `ctrl.value` reads don't re-render an OnPush view on an *external* patch
  // (e.g. loading an existing record into the form), only on a local user
  // event — see `fileCtrlValue`'s doc comment for the confirmed-live proof.
  readonly preferredCurrency  = this.currency.preferredCurrency;
  readonly currencyRatesList  = this.currency.rates;
  private readonly currencyCtrlValue = signal<unknown>(null);
  private currencyCtrlValueSub?: Subscription;

  // ── Lookup state ──────────────────────────────────────────────────────────
  readonly lookupSearch  = signal('');
  readonly lookupOpen    = signal(false);
  readonly lookupItems   = signal<{ id: string; label: string }[]>([]);
  readonly lookupLoading = signal(false);
  readonly lookupLabel   = signal('');

  private searchTimer: ReturnType<typeof setTimeout> | null = null;
  private lookupSub?: Subscription;

  // ── File upload state (P-file-upload-pipeline, D-144's two-call flow) ─────
  readonly fileState        = signal<'idle' | 'uploading' | 'processing' | 'rejected' | 'error'>('idle');
  readonly fileProgress     = signal(0);
  readonly fileMessage      = signal<string | null>(null);
  readonly downloading      = signal(false);
  private readonly fileInitialValue = signal<unknown>(null);
  // The file `<input>` deliberately has no `[formControlName]` (browsers
  // won't let one pre-fill a file input's value) — so unlike every other
  // field type here, nothing else marks this OnPush view for check when the
  // control changes from outside this component (e.g. the host form
  // re-patching after navigating between records). Mirroring the value into
  // this signal — read by `fileDisplayName`/`canDownload` below instead of
  // `ctrl.value` directly — is what reschedules the view's check on a write,
  // in place of an explicit manual change-detection call.
  private readonly fileCtrlValue = signal<unknown>(null);
  private fileCtrlValueSub?: Subscription;

  // create-session -> PUT -> finalize -> poll, shared with
  // `image-upload.component.ts` (upload-pipeline.ts).
  private readonly pipeline = new UploadPipeline(this.fileSvc);

  // ── Form control access ───────────────────────────────────────────────────
  get ctrl(): AbstractControl {
    return (this.cc.control as FormGroup).get(this.field().name)!;
  }

  // ── Field-type helpers ────────────────────────────────────────────────────
  private get lookupOpts(): LookupOptions | null {
    return this.field().field_type === 'lookup'
      ? (this.field().options as LookupOptions | null)
      : null;
  }

  private get choiceOpts(): ChoiceOptions | null {
    return this.field().field_type === 'choice'
      ? (this.field().options as ChoiceOptions | null)
      : null;
  }

  private get fileOpts(): FileOptions | null {
    return this.field().field_type === 'file'
      ? (this.field().options as FileOptions | null)
      : null;
  }

  isMulti():     boolean  { return !!(this.choiceOpts?.multi); }
  isFileMulti(): boolean  { return !!(this.fileOpts?.multi); }
  /** The choices, limited to what the record's rules allow now (A6-T2). */
  choices(): string[] {
    const all = this.choiceOpts?.choices ?? [];
    const allowed = this.policy?.allowedValues?.(this.field().name);
    return allowed ? all.filter(c => allowed.includes(c)) : all;
  }

  /** A6-T2: the value a rule just cleared from this field, while it can be undone. */
  readonly clearedNote = computed(() => this.policy?.clearedValue?.(this.field().name) ?? null);

  undoClear(): void {
    this.policy?.undoClear?.(this.field().name);
  }

  /** M05/D-426 — `c`'s resolved label, falling back to the raw stored value
   * when no translation exists (untouched behavior for an untranslated
   * deployment). The submitted form value stays the raw choice value either
   * way — only the on-screen text changes. */
  choiceLabel(c: string): string {
    return this.choiceOpts?.option_labels?.[c] ?? c;
  }

  isSelected(c: string): boolean {
    const v = this.ctrl?.value;
    return Array.isArray(v) ? v.includes(c) : v === c;
  }

  showRequiredError(): boolean {
    return this.field().is_required && this.ctrl.invalid && this.ctrl.touched;
  }

  /** A3-T7: a failed pattern, format or range check, once the field was
   * touched; `required` shows on its own. */
  checkError(): { key: string; params: Record<string, unknown> } | null {
    if (!this.ctrl || !(this.ctrl.touched || this.ctrl.dirty)) return null;
    return checkFailure(this.ctrl.errors);
  }

  toggleChoice(c: string): void {
    if (!this.isMulti()) { this.ctrl.setValue(c); return; }
    const v: string[] = Array.isArray(this.ctrl.value) ? [...this.ctrl.value] : [];
    const idx = v.indexOf(c);
    if (idx >= 0) v.splice(idx, 1); else v.push(c);
    this.ctrl.setValue(v);
    this.ctrl.markAsDirty();
  }

  /**
   * C-29 (M01 §7) — prefers the field's own metadata (`TextOptions.text_type`,
   * attome-field's additive `options` field) over guessing from the field
   * *name*. A field created before this option existed has no `text_type`
   * set, so the name-based heuristic below stays as the fallback — nothing
   * regresses for an untouched deployment, and an admin can now override it
   * explicitly through the field editor for any field, named however it
   * likes.
   */
  textType(): string {
    const configured = this.field().field_type === 'text'
      ? (this.field().options as TextOptions | null)?.text_type
      : null;
    if (configured) return configured;

    const name = this.field().name.toLowerCase();
    if (name === 'email' || name.endsWith('_email')) return 'email';
    if (name === 'phone' || name.endsWith('_phone')) return 'tel';
    if (name === 'url'   || name.endsWith('_url')
     || name === 'link'  || name.endsWith('_link')
     || name === 'website') return 'url';
    return 'text';
  }

  textPlaceholder(): string {
    switch (this.textType()) {
      case 'email': return 'name@example.com';
      case 'tel':   return '+1...';
      case 'url':   return 'https://...';
      default:      return '';
    }
  }

  // ── Currency methods (D-490) ──────────────────────────────────────────────
  currencyCodes(): string[] { return this.currencyRatesList().map(r => r.code); }

  currencyIcon(): string { return this.currency.getRate(this.preferredCurrency()).icon; }

  /** The stored USD amount, converted to the viewer's preferred currency.
   *  Rounded to cents for display — the conversion multiply routinely
   *  produces float noise (e.g. 0.9199999999999999) that would otherwise
   *  show up verbatim in the input. */
  currencyDisplayValue(): number {
    const raw = Number(this.currencyCtrlValue() ?? 0);
    if (!Number.isFinite(raw)) return 0;
    return Math.round(this.currency.fromBase(raw, this.preferredCurrency()) * 100) / 100;
  }

  /** Writes the field's control (always USD) from a display-currency input. */
  onCurrencyAmountInput(displayed: string): void {
    if (displayed.trim() === '') {
      this.ctrl.setValue(null);
      this.ctrl.markAsDirty();
      return;
    }
    const n = Number(displayed);
    if (!Number.isFinite(n)) return;
    this.ctrl.setValue(this.currency.toBase(n, this.preferredCurrency()));
    this.ctrl.markAsDirty();
  }

  /** Switches the viewer's preferred display currency app-wide (D-490 —
   *  `localStorage` only, not persisted to the user's account). */
  onCurrencyCodeChange(code: string): void {
    this.currency.setPreferredCurrency(code);
  }

  /**
   * Field types whose control needs more than one form column — the file
   * field's upload progress/status block, and a multi-choice field's wrapping
   * checkbox row. A lookup stays column-width: its popup is positioned to the
   * control, so it behaves like a select.
   */
  isWideField(): boolean {
    const t = this.field().field_type;
    return t === 'file' || t === 'rich_text' || (t === 'choice' && this.isMulti());
  }

  // ── Formula methods (U9, D-604) ───────────────────────────────────────────
  private get formulaOpts(): FormulaOptions | null {
    return this.field().field_type === 'formula'
      ? (this.field().options as FormulaOptions | null)
      : null;
  }

  formulaExpression(): string { return this.formulaOpts?.expression ?? ''; }

  /** The computed value, formatted for its declared result type. */
  formulaDisplay(): string {
    const v = this.formulaCtrlValue();
    if (v === null || v === undefined || v === '') return this.lang.translate('fieldInput.formulaEmpty');
    switch (this.formulaOpts?.result_type) {
      case 'bool':
        return this.lang.translate(v === true || v === 'true' ? 'fieldInput.formulaTrue' : 'fieldInput.formulaFalse');
      case 'date': {
        const d = new Date(String(v));
        return Number.isNaN(d.getTime()) ? String(v) : d.toLocaleString();
      }
      case 'number':
      case 'currency': {
        const n = Number(v);
        return Number.isFinite(n) ? n.toLocaleString() : String(v);
      }
      default:
        return String(v);
    }
  }

  // ── Lookup methods ────────────────────────────────────────────────────────
  openLookup(): void {
    this.lookupOpen.set(true);
    this.lookupSearch.set('');
    this.fetchLookup('');
    setTimeout(() => this.searchInputRef()?.nativeElement.focus(), 0);
  }

  closeLookup(): void { this.lookupOpen.set(false); }

  clearLookup(): void {
    this.ctrl.setValue(null);
    this.ctrl.markAsDirty();
    this.lookupLabel.set('');
  }

  selectLookup(item: { id: string; label: string }): void {
    this.ctrl.setValue(item.id);
    this.ctrl.markAsDirty();
    this.lookupLabel.set(item.label);
    this.closeLookup();
  }

  onLookupKeydown(event: KeyboardEvent, item: { id: string; label: string }): void {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    this.selectLookup(item);
  }

  onSearchInput(value: string): void {
    this.lookupSearch.set(value);
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => this.fetchLookup(value), 200);
  }

  private fetchLookup(search: string): void {
    const opts = this.lookupOpts;
    if (!opts?.target_entity_name) return;
    // A slower earlier keystroke's response arriving after a faster later
    // one would otherwise overwrite the fresher results — cancel it instead.
    this.lookupSub?.unsubscribe();
    this.lookupLoading.set(true);
    this.lookupSub = this.svc.lookupSearch(opts.target_entity_name, search, opts.display_field).subscribe({
      next: res => {
        this.lookupLoading.set(false);
        this.lookupItems.set(res.data.map(r => ({
          id:    r.id,
          label: this.resolveLabel(r, opts.display_field),
        })));
      },
      error: () => { this.lookupLoading.set(false); this.lookupItems.set([]); },
    });
  }

  // Structural, not `EntityRecord`/`EntityRecordResponse`: this is called both
  // with a `list()` row (client-reshaped) and with a `get()` response (the
  // generated wire type), and it only ever reads these two members.
  private resolveLabel(r: { id: string; data: Record<string, unknown> }, displayField: string | null): string {
    if (displayField && r.data[displayField] != null) return String(r.data[displayField]);
    for (const k of ['name', 'title', 'label', 'display_name']) {
      if (r.data[k] != null) return String(r.data[k]);
    }
    return r.id;
  }

  // ── File methods ──────────────────────────────────────────────────────────
  /**
   * Whether the file control currently holds a value — reads the `fileCtrlValue`
   * signal rather than `ctrl.value` directly. This is what the template's outer
   * `@if` gates the whole "file-current" block on: because it's the outermost,
   * unconditionally-evaluated read, it registers this OnPush view's dependency
   * on the signal from the very first render, before the block's own truthiness
   * is even known. Reading the signal only inside the (initially-false) inner
   * block would never establish that dependency, so a later external write
   * (the host form patching this control) would silently fail to reschedule a
   * check — confirmed live: `fixture.detectChanges()` alone did not re-render it.
   */
  hasFileValue(): boolean { return !!this.fileCtrlValue(); }

  fileDisplayName(): string {
    const key = this.fileCtrlValue();
    if (typeof key !== 'string' || !key) return '';
    const last = key.split('/').pop() ?? key;
    // final_key's shape is `{session_id}-{filename}` (files.rs::final_key) —
    // session_id is always a 36-char UUID, so the filename starts at index 37.
    return last.length > 37 ? last.slice(37) : last;
  }

  // A locally-set value (just uploaded, not yet saved on the record) can't be
  // downloaded yet — get_download_url reads the *persisted* column, not the
  // form's pending value.
  canDownload(): boolean {
    const v = this.fileCtrlValue();
    return !!v && v === this.fileInitialValue();
  }

  async onFileSelected(files: FileList | null): Promise<void> {
    const file = files?.[0];
    const entityName = this.entityName();
    const recordId = this.recordId();
    if (!file || !entityName || !recordId) return;

    this.fileState.set('uploading');
    this.fileProgress.set(0);
    this.fileMessage.set(null);

    const result = await this.pipeline.run(
      { entityName, recordId, fieldName: this.field().name },
      file,
      {
        onPhase:    phase   => this.fileState.set(phase),
        onProgress: percent => this.fileProgress.set(percent),
      },
    );

    if (result.kind === 'clean') {
      this.ctrl.setValue(result.finalKey);
      this.ctrl.markAsDirty();
      this.fileState.set('idle');
      this.fileMessage.set(null);
    } else {
      this.fileState.set(result.kind === 'rejected' ? 'rejected' : 'error');
      this.fileMessage.set(result.message);
    }
  }

  downloadFile(): void {
    const entityName = this.entityName();
    const recordId = this.recordId();
    if (!entityName || !recordId) return;
    this.downloading.set(true);
    this.fileSvc.getDownloadUrl(entityName, recordId, this.field().name).subscribe({
      next: res => {
        this.downloading.set(false);
        window.open(res.download_url, '_blank', 'noopener');
      },
      error: () => { this.downloading.set(false); },
    });
  }

  /** U18 — see `AttachmentComponent.onVersionRestored`. */
  onFileVersionRestored(res: RestoreVersionResponse): void {
    this.fileInitialValue.set(res.object_key);
    this.ctrl.setValue(res.object_key);
    this.fileState.set('idle');
    this.fileMessage.set(null);
  }

  clearFile(): void {
    this.ctrl.setValue(null);
    this.ctrl.markAsDirty();
    this.fileState.set('idle');
    this.fileMessage.set(null);
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────
  ngOnInit(): void {
    const opts  = this.lookupOpts;
    const value = this.ctrl?.value;
    if (opts?.target_entity_name && value) {
      this.svc.get(opts.target_entity_name, value).subscribe({
        next: r => this.lookupLabel.set(this.resolveLabel(r, opts.display_field)),
      });
    }
    if (this.field().field_type === 'file') {
      this.fileInitialValue.set(value ?? null);
      this.fileCtrlValue.set(value ?? null);
      this.fileCtrlValueSub = this.ctrl.valueChanges.subscribe(v => this.fileCtrlValue.set(v));
    }
    if (this.field().field_type === 'currency') {
      this.currencyCtrlValue.set(value ?? null);
      this.currencyCtrlValueSub = this.ctrl.valueChanges.subscribe(v => this.currencyCtrlValue.set(v));
    }
    if (this.field().field_type === 'formula') {
      this.formulaCtrlValue.set(value ?? null);
      this.formulaCtrlValueSub = this.ctrl.valueChanges.subscribe(v => this.formulaCtrlValue.set(v));
    }
  }

  ngOnDestroy(): void {
    this.closeScan();
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.pipeline.cancel();
    this.fileCtrlValueSub?.unsubscribe();
    this.currencyCtrlValueSub?.unsubscribe();
    this.formulaCtrlValueSub?.unsubscribe();
    this.lookupSub?.unsubscribe();
  }

  onEscape(): void { this.lookupOpen.set(false); }
}
