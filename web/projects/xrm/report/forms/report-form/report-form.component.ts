import { ChangeDetectionStrategy, Component, DestroyRef, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ReactiveFormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';
import { ReportRunService, ReportRunStatus, isTerminalRun } from '../../services/report-run.service';

/** The runner's visible state: idle, in flight, or one of the three outcomes. */
export type ReportRunState = 'idle' | 'running' | 'completed' | 'failed' | 'timeout';

/**
 * Hand-coded form for `attome_report`, scaffolded from platform-bundles/attome-report-reports.json's
 * "synthesized (no authored layout)" layout by scripts/bundle-to-form-component.mjs. Same
 * field-rendering approach as the generic dispatcher (<attome-field-input> per
 * schema field), but its own component/template — edit freely; re-running
 * the generator only overwrites this file with --force.
 *
 * Tab/section/field grouping below mirrors the bundle's layout at
 * generation time. The bundle JSON remains the source of truth for the
 * entity/fields themselves (schema, validation, choices) — only the form's
 * *presentation* moved to hand-written code.
 */
@Component({
  selector:   'attome-report-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, TranslatePipe, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent],
  styleUrls:  ['../../../styles/xrm-form.css', './report-form.component.css'],
  templateUrl: './report-form.component.html',
})
export class ReportFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);
  private readonly runs       = inject(ReportRunService);
  private readonly runDestroy = inject(DestroyRef);

  // ── U16 (M25) — Run → poll → download ────────────────────────────────────
  readonly runState = signal<ReportRunState>('idle');
  readonly lastRun  = signal<ReportRunStatus | null>(null);
  readonly runError = signal<string | null>(null);

  /**
   * Runs the **saved** report definition (the server reads format, query and
   * parameters from the record), so it is offered only on a saved,
   * unmodified record — running while the form holds unsaved edits would
   * silently run the previous definition.
   */
  runReport(): void {
    const id = this.id();
    if (!id || this.runState() === 'running' || this.dirty()) return;
    this.runState.set('running');
    this.lastRun.set(null);
    this.runError.set(null);
    this.runs.runAndWait(id).pipe(takeUntilDestroyed(this.runDestroy)).subscribe({
      next: run => {
        this.lastRun.set(run);
        if (!isTerminalRun(run)) { this.runState.set('timeout'); return; }
        if (run.status === 'failed') {
          this.runState.set('failed');
          this.runError.set(run.error ?? null);
          return;
        }
        this.runState.set('completed');
        // A popup blocker may refuse this (it is no longer inside the click's
        // user gesture); the template's download link is the fallback.
        if (run.download_url) window.open(run.download_url, '_blank', 'noopener');
      },
      error: (e: ApiError) => {
        this.runState.set('failed');
        this.runError.set(e.message);
      },
    });
  }
  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'details', label: 'Details', icon: 'las la-list-alt' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }

  /** Looks up loaded schema fields by logicalname, in this form's fixed layout order. */
  protected fieldsIn(names: string[]): FieldSchema[] {
    const all = this.schema()?.fields ?? [];
    return names.map(n => all.find(f => f.name === n)).filter((f): f is FieldSchema => !!f);
  }
}
