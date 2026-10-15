import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  CandidateExplanation, DuplicateCandidate, DuplicateStats, DuplicatesService, MATCH_COMPARATORS,
  MatchComparator, MatchField, MatchRule, MergeResponse, ON_SAVE_MODES, OnSave, RulePreview,
} from '@attome/xrm/core/admin/data';
import { MergeDialogComponent, MergeUndoBarComponent } from '@attome/xrm/core/entity';

/** Catalogue keys, spelled out so the catalogue coverage check sees each one. */
const COMPARATOR_KEYS: Record<MatchComparator, string> = {
  exact: 'duplicatesManager.comparator_exact',
  normalized: 'duplicatesManager.comparator_normalized',
  trigram: 'duplicatesManager.comparator_trigram',
  embedding: 'duplicatesManager.comparator_embedding',
  phone: 'duplicatesManager.comparator_phone',
  email: 'duplicatesManager.comparator_email',
  id: 'duplicatesManager.comparator_id',
  name: 'duplicatesManager.comparator_name',
  phonetic: 'duplicatesManager.comparator_phonetic',
};

const ON_SAVE_KEYS: Record<OnSave, string> = {
  off: 'duplicatesManager.onSave_off',
  warn: 'duplicatesManager.onSave_warn',
  allow_with_reason: 'duplicatesManager.onSave_allow_with_reason',
  block: 'duplicatesManager.onSave_block',
};

/** One field row of the rule editor. */
interface DraftField {
  field: string;
  comparator: MatchComparator;
  weight: number;
}

/**
 * D-432 / M13, A15-T10 — the duplicate review queue.
 *
 * - Pairs the sweep and scans found (`duplicate_candidate`, open only): Merge
 *   opens the side-by-side merge dialog (record A stays unless swapped; the
 *   merge closes the pair in the same transaction), followed by an Undo bar;
 *   Not a match dismisses the pair so it is never suggested again; Why?
 *   shows the explain panel, field by field (comparator, weight, score and
 *   both stored keys).
 * - Counts per entity (open, merged, not a match).
 * - The match rules: each with its on-save mode, last scan and a Scan now
 *   button (a resumable full-table job), and a rule editor offering every
 *   runnable comparator and on-save mode, a Preview over a sample of live
 *   rows before saving, and Suggest rules (the `duplicates.propose_rules`
 *   agent action, which saves nothing: its draft fills the editor).
 */
@Component({
  selector: 'xrm-duplicates-manager',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe, FormsModule, TranslatePipe, MergeDialogComponent, MergeUndoBarComponent],
  styleUrls: ['../../../styles/admin-page.css', './duplicates-manager.component.css'],
  templateUrl: './duplicates-manager.component.html',
})
export class DuplicatesManagerComponent implements OnInit {
  private readonly svc = inject(DuplicatesService);
  private readonly lang = inject(LangService);

  readonly comparators = MATCH_COMPARATORS;
  readonly onSaveModes = ON_SAVE_MODES;
  readonly comparatorKey = (c: MatchComparator): string => COMPARATOR_KEYS[c];
  readonly onSaveKey = (m: OnSave): string => ON_SAVE_KEYS[m];

  readonly items = signal<DuplicateCandidate[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly busyId = signal<string | null>(null);
  readonly entityFilter = signal('');

  readonly stats = signal<DuplicateStats[]>([]);
  readonly rules = signal<MatchRule[]>([]);
  readonly scanNote = signal<Record<string, string>>({});

  /** The pair whose merge dialog is open. */
  readonly merging = signal<DuplicateCandidate | null>(null);
  /** The last merge made here, for its Undo bar. */
  readonly lastMerge = signal<{ entity: string; mergeId: string } | null>(null);
  readonly dismissingId = signal<string | null>(null);
  readonly dismissNote = signal('');
  readonly explainingId = signal<string | null>(null);
  readonly explanation = signal<CandidateExplanation | null>(null);

  // ── Rule editor ────────────────────────────────────────────────────────
  readonly editorOpen = signal(false);
  readonly draftEntity = signal('');
  readonly draftName = signal('');
  readonly draftThreshold = signal(0.8);
  readonly draftOnSave = signal<OnSave>('warn');
  readonly draftFields = signal<DraftField[]>([{ field: '', comparator: 'normalized', weight: 1 }]);
  readonly rulePreview = signal<RulePreview | null>(null);
  readonly editorBusy = signal(false);
  readonly editorError = signal<string | null>(null);
  readonly canSubmitRule = computed(() =>
    !!this.draftEntity().trim() && this.draftFields().some(f => f.field.trim()) && !this.editorBusy());

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    const entity = this.entityFilter().trim() || undefined;
    this.svc.listCandidates(1, 50, 'open', entity).subscribe({
      next: res => { this.items.set(res.items); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(this.lang.errorText(e)); this.loading.set(false); },
    });
    this.svc.stats(entity).subscribe({ next: s => this.stats.set(s), error: () => this.stats.set([]) });
    this.svc.listMatchRules(1, 100, entity).subscribe({ next: r => this.rules.set(r.items), error: () => this.rules.set([]) });
  }

  // ── Pairs ──────────────────────────────────────────────────────────────

  openMerge(c: DuplicateCandidate): void {
    this.dismissingId.set(null);
    this.explainingId.set(null);
    this.merging.set(c);
  }

  onMerged(c: DuplicateCandidate, result: MergeResponse): void {
    this.merging.set(null);
    this.lastMerge.set({ entity: c.entity_logicalname, mergeId: result.merge_log_id });
    this.load();
  }

  onUndone(): void {
    this.lastMerge.set(null);
    this.load();
  }

  toggleDismiss(c: DuplicateCandidate): void {
    if (this.dismissingId() === c.id) {
      this.dismissingId.set(null);
    } else {
      this.dismissingId.set(c.id);
      this.merging.set(null);
      this.dismissNote.set('');
    }
  }

  confirmDismiss(c: DuplicateCandidate): void {
    this.busyId.set(c.id);
    this.svc.dismissCandidate(c.id, c.row_version, this.dismissNote().trim() || undefined).subscribe({
      next: () => { this.busyId.set(null); this.dismissingId.set(null); this.load(); },
      error: (e: ApiError) => { this.busyId.set(null); this.error.set(this.lang.errorText(e)); },
    });
  }

  toggleExplain(c: DuplicateCandidate): void {
    if (this.explainingId() === c.id) {
      this.explainingId.set(null);
      return;
    }
    this.explainingId.set(c.id);
    this.explanation.set(null);
    this.svc.explainCandidate(c.id).subscribe({
      next: x => { if (this.explainingId() === c.id) this.explanation.set(x); },
      error: (e: ApiError) => { this.explainingId.set(null); this.error.set(this.lang.errorText(e)); },
    });
  }

  percent(score: number | null): string {
    return score === null ? '' : `${Math.round(score * 100)}%`;
  }

  // ── Rules ──────────────────────────────────────────────────────────────

  fieldsText(rule: MatchRule): string {
    return rule.fields
      .map(f => `${f.field} (${this.lang.translate(COMPARATOR_KEYS[f.comparator])})`)
      .join(', ');
  }

  scan(rule: MatchRule): void {
    this.busyId.set(rule.id);
    this.svc.scanMatchRule(rule.id).subscribe({
      next: r => {
        this.busyId.set(null);
        const key = r.queued ? 'duplicatesManager.scanQueued' : 'duplicatesManager.scanRunning';
        this.scanNote.update(m => ({ ...m, [rule.id]: this.lang.translate(key) }));
      },
      error: (e: ApiError) => {
        this.busyId.set(null);
        this.scanNote.update(m => ({ ...m, [rule.id]: this.lang.errorText(e) }));
      },
    });
  }

  openEditor(): void {
    this.editorOpen.set(true);
    this.editorError.set(null);
    this.rulePreview.set(null);
    if (!this.draftEntity()) this.draftEntity.set(this.entityFilter().trim());
  }

  addField(): void {
    this.draftFields.update(f => [...f, { field: '', comparator: 'normalized', weight: 1 }]);
  }

  removeField(index: number): void {
    this.draftFields.update(f => f.filter((_, i) => i !== index));
  }

  setField(index: number, patch: Partial<DraftField>): void {
    this.draftFields.update(f => f.map((row, i) => (i === index ? { ...row, ...patch } : row)));
    this.rulePreview.set(null);
  }

  private wireFields(): MatchField[] {
    return this.draftFields()
      .filter(f => f.field.trim())
      .map(f => ({ field: f.field.trim(), comparator: f.comparator, weight: Number(f.weight) || 1, min_similarity: null }));
  }

  previewRule(): void {
    this.editorBusy.set(true);
    this.editorError.set(null);
    this.svc.previewMatchRule({
      entity: this.draftEntity().trim(), fields: this.wireFields(), threshold: Number(this.draftThreshold()),
    }).subscribe({
      next: p => { this.editorBusy.set(false); this.rulePreview.set(p); },
      error: (e: ApiError) => { this.editorBusy.set(false); this.editorError.set(this.lang.errorText(e)); },
    });
  }

  /** `duplicates.propose_rules`: the model's draft fills the editor; nothing is saved. */
  suggestRules(): void {
    this.editorBusy.set(true);
    this.editorError.set(null);
    this.svc.proposeRules(this.draftEntity().trim()).subscribe({
      next: proposal => {
        this.editorBusy.set(false);
        if (!proposal) {
          this.editorError.set(this.lang.translate('duplicatesManager.suggestFailed'));
          return;
        }
        this.draftFields.set(proposal.draft.fields.map(f => ({ field: f.field, comparator: f.comparator, weight: f.weight })));
        this.draftThreshold.set(proposal.draft.threshold);
        this.rulePreview.set(proposal.preview);
      },
      error: (e: ApiError) => { this.editorBusy.set(false); this.editorError.set(this.lang.errorText(e)); },
    });
  }

  saveRule(): void {
    const entity = this.draftEntity().trim();
    this.editorBusy.set(true);
    this.editorError.set(null);
    this.svc.createMatchRule({
      entity,
      name: this.draftName().trim() || entity,
      fields: this.wireFields(),
      threshold: Number(this.draftThreshold()),
      on_save: this.draftOnSave(),
    }).subscribe({
      next: () => {
        this.editorBusy.set(false);
        this.editorOpen.set(false);
        this.draftName.set('');
        this.draftFields.set([{ field: '', comparator: 'normalized', weight: 1 }]);
        this.rulePreview.set(null);
        this.load();
      },
      error: (e: ApiError) => { this.editorBusy.set(false); this.editorError.set(this.lang.errorText(e)); },
    });
  }
}
