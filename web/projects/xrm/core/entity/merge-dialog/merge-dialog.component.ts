import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal, untracked } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { DuplicatesService, MergePicks, MergePreview, MergeResponse } from '@attome/xrm/core/admin/data';
import { forkJoin } from 'rxjs';
import { EntityRecordResponse, EntityService } from '../services/entity.service';

/** One field row of the side-by-side view. */
export interface MergeFieldRow {
  name: string;
  label: string;
  survivor: string;
  merged: string;
  /** Both records hold the same value: nothing to pick. */
  same: boolean;
}

type Side = 'survivor' | 'merged';

/** How a record value reads in the dialog. */
function display(record: EntityRecordResponse, field: string): string {
  const lookup = (record as { lookups?: Record<string, { name?: string | null } | undefined> }).lookups?.[field];
  if (lookup?.name) return lookup.name;
  const value = (record.data as Record<string, unknown>)[field];
  if (value === null || value === undefined || value === '') return '';
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

/**
 * A15-T10: merges two records attribute by attribute. The records sit side by
 * side with a radio per field that differs; the defaults are what the
 * entity's survivorship rules would keep (the server's merge preview with no
 * picks), and every change of a pick asks the preview again, so the result
 * column, the related rows that move, the flows the merge starts and the
 * merge mode are always the server's own answer before Confirm. Confirm
 * sends the picks with the merge (`POST /{entity}/{id}/merge`, `picks`).
 * Swap makes the other record the survivor.
 *
 * The API merges a pair; three or more duplicates are merged one pair at a
 * time into the same survivor.
 */
@Component({
  selector: 'xrm-merge-dialog',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../../../styles/inline-actions.css', './merge-dialog.component.css'],
  templateUrl: './merge-dialog.component.html',
})
export class MergeDialogComponent {
  private readonly entities = inject(EntityService);
  private readonly duplicates = inject(DuplicatesService);
  private readonly lang = inject(LangService);

  readonly entity = input.required<string>();
  readonly survivorId = input.required<string>();
  readonly mergedId = input.required<string>();
  /** The queue row this merge settles, when it came from one. */
  readonly candidateId = input<string | null>(null);

  readonly merged = output<MergeResponse>();
  readonly cancelled = output<void>();

  /** The record that survives (Swap flips it). */
  readonly survivor = signal<string>('');
  readonly other = signal<string>('');
  readonly records = signal<{ survivor: EntityRecordResponse; merged: EntityRecordResponse } | null>(null);
  readonly labels = signal<Record<string, string>>({});
  readonly picks = signal<Record<string, Side>>({});
  readonly preview = signal<MergePreview | null>(null);
  readonly loading = signal(true);
  readonly merging = signal(false);
  readonly error = signal<string | null>(null);

  /** Every field either record holds, in schema order. */
  readonly rows = computed<MergeFieldRow[]>(() => {
    const recs = this.records();
    if (!recs) return [];
    const labels = this.labels();
    const a = recs.survivor.data as Record<string, unknown>;
    const b = recs.merged.data as Record<string, unknown>;
    return Object.keys(labels)
      .filter(name => display(recs.survivor, name) !== '' || display(recs.merged, name) !== '')
      .map(name => ({
        name,
        label: labels[name],
        survivor: display(recs.survivor, name),
        merged: display(recs.merged, name),
        same: same(a[name], b[name]),
      }));
  });

  /** What the survivor will hold, per field, after the merge. */
  readonly result = computed<Record<string, string>>(() => {
    const recs = this.records();
    if (!recs) return {};
    const out: Record<string, string> = {};
    for (const row of this.rows()) {
      out[row.name] = this.picks()[row.name] === 'merged' ? row.merged : row.survivor;
    }
    return out;
  });

  readonly movedTotal = computed(() => (this.preview()?.moved ?? []).reduce((n, m) => n + m.count, 0));

  constructor() {
    effect(() => {
      const survivor = this.survivorId();
      const merged = this.mergedId();
      untracked(() => {
        this.survivor.set(survivor);
        this.other.set(merged);
        this.load();
      });
    });
  }

  swap(): void {
    const s = this.survivor();
    this.survivor.set(this.other());
    this.other.set(s);
    this.load();
  }

  pick(field: string, side: Side): void {
    this.picks.update(p => ({ ...p, [field]: side }));
    this.refreshPreview();
  }

  private load(): void {
    const entity = this.entity();
    this.loading.set(true);
    this.error.set(null);
    this.preview.set(null);
    forkJoin({
      schema: this.entities.getSchema(entity),
      survivor: this.entities.get(entity, this.survivor()),
      merged: this.entities.get(entity, this.other()),
      preview: this.duplicates.mergePreview(entity, this.survivor(), this.other()),
    }).subscribe({
      next: ({ schema, survivor, merged, preview }) => {
        const labels: Record<string, string> = {};
        for (const f of [...schema.fields].sort((x, y) => x.sort_order - y.sort_order)) {
          labels[f.name] = f.display_name || f.name;
        }
        this.labels.set(labels);
        this.records.set({ survivor, merged });
        // Defaults: what the survivorship rules keep.
        const picks: Record<string, Side> = {};
        const mergedData = merged.data as Record<string, unknown>;
        const survivorData = survivor.data as Record<string, unknown>;
        for (const name of Object.keys(labels)) {
          if (same(survivorData[name], mergedData[name])) continue;
          picks[name] = name in preview.result && same(preview.result[name], mergedData[name]) ? 'merged' : 'survivor';
        }
        this.picks.set(picks);
        this.preview.set(preview);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  /** The picks the merge sends: only the fields where the records differ. */
  private wirePicks(): MergePicks {
    const out: MergePicks = {};
    for (const row of this.rows()) {
      if (!row.same && this.picks()[row.name]) out[row.name] = this.picks()[row.name];
    }
    return out;
  }

  private refreshPreview(): void {
    this.duplicates.mergePreview(this.entity(), this.survivor(), this.other(), this.wirePicks()).subscribe({
      next: p => this.preview.set(p),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  confirm(): void {
    const recs = this.records();
    if (!recs || !this.preview()) return;
    this.merging.set(true);
    this.error.set(null);
    this.duplicates.mergeRecords(this.entity(), this.survivor(), this.other(), {
      picks: this.wirePicks(),
      candidateId: this.candidateId() ?? undefined,
      rowVersion: recs.survivor.row_version,
    }).subscribe({
      next: r => {
        this.merging.set(false);
        this.merged.emit(r);
      },
      error: (e: ApiError) => {
        this.merging.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}
