import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ReactiveFormsModule } from '@angular/forms';
import { ApiService, LangService, TranslatePipe } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';

/** P9-T11: the privilege certification needs. */
export const CERTIFY_PRIVILEGE = 'attome_metric.certify';

/** The certify route's answer (P9-T11). */
interface MetricCertification {
  metric_id: string;
  certified: boolean;
  certified_at: string | null;
}

/**
 * Hand-coded form for `dashboard_metric_definition`, on the shared base form
 * (D-773). P9-T14: the definition's own fields, the builder's parts (P9-T3)
 * and its governance. `certified` and `certified_at` are engine-managed: the
 * form shows them and a holder of `attome_metric.certify` changes them
 * through `POST /api/v1/metrics/{id}/certify`, never through a save.
 */
@Component({
  selector:   'attome-dashboard-metric-definition-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, TranslatePipe, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent],
  styleUrls:  ['../../../styles/xrm-form.css', './dashboard-metric-definition-form.component.css'],
  templateUrl: './dashboard-metric-definition-form.component.html',
})
export class DashboardMetricDefinitionFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);
  private readonly api = inject(ApiService);
  private readonly access = inject(AccessService);
  private readonly destroyed = inject(DestroyRef);

  readonly certifying = signal(false);
  readonly certifyFailed = signal(false);
  /** As stored; a save never changes it. */
  readonly certified = computed(() => this.recordValue()['certified'] === true);
  readonly certifiedAt = computed(() => {
    const at = this.recordValue()['certified_at'];
    return typeof at === 'string' ? at : null;
  });
  readonly canCertify = computed(() => this.isEdit() && this.access.hasPrivilege(CERTIFY_PRIVILEGE));

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'details', label: this.lang.translate('xrmForm.tabs.details'), icon: 'las la-list-alt' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }

  /** Looks up loaded schema fields by logicalname, in this form's fixed layout order. */
  protected fieldsIn(names: string[]): FieldSchema[] {
    const all = this.schema()?.fields ?? [];
    return names.map(n => all.find(f => f.name === n)).filter((f): f is FieldSchema => !!f);
  }

  /** Certifies the metric, or withdraws it, then reloads the record. */
  setCertified(value: boolean): void {
    const id = this.id();
    if (!id || this.certifying()) return;
    this.certifying.set(true);
    this.certifyFailed.set(false);
    this.api.post<MetricCertification>(`/api/v1/metrics/${encodeURIComponent(id)}/certify`, { certified: value })
      .pipe(takeUntilDestroyed(this.destroyed))
      .subscribe({
        next: () => {
          this.certifying.set(false);
          this.reload();
        },
        error: () => {
          this.certifying.set(false);
          this.certifyFailed.set(true);
        },
      });
  }
}
