import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import { LangService, TranslatePipe } from '@attome/base';
import type { FieldChangeResult } from '@attome/xrm/core/admin/data';

/**
 * Renders what a field structure change did or (dry run, blocked) would do:
 * the refusal and its blockers, the objects that use the field, the counts
 * (values archived, values that do not convert, records keeping a removed
 * choice) and the release-report items it wrote. Display only.
 */
@Component({
  selector: 'attome-field-change-result',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./field-change-result.component.css'],
  templateUrl: './field-change-result.component.html',
})
export class FieldChangeResultComponent {
  private readonly lang = inject(LangService);

  readonly result = input.required<FieldChangeResult>();

  readonly blocked = computed(() => this.result().error !== null && this.result().error !== undefined);

  /** The refusal in plain words (catalog text for the stable code). */
  readonly blockedText = computed(() => {
    const code = this.result().error;
    if (!code) return '';
    const key = `structureErrors.${code}`;
    const text = this.lang.translate(key);
    return text === key ? this.lang.translate('fieldChange.result.blocked') : text;
  });

  readonly headline = computed(() => {
    if (this.blocked()) return 'fieldChange.result.blocked';
    return this.result().dry_run ? 'fieldChange.result.dryRun' : 'fieldChange.result.done';
  });

  readonly isRetype = computed(() => this.result().op === 'change_field_type');
  readonly isDelete = computed(() => this.result().op === 'delete_field');

  /** A dry-run type change on a large table cannot count its failures up front. */
  readonly notConvertibleUnknown = computed(() =>
    this.isRetype() && this.result().dry_run && this.result().not_convertible === null);

  ownerKey(owner: string): string {
    return owner === 'customer' ? 'fieldChange.result.customer' : 'fieldChange.result.ours';
  }

  reportKindKey(kind: string): string { return `releaseReport.kinds.${kind}`; }
}
