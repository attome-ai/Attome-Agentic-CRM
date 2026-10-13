import { ChangeDetectionStrategy, Component, OnChanges, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { TitleCasePipe } from '@angular/common';
import { ApiError } from '@attome/base';
import { CaptureBaselineResponse, ProjectService, ProjectSummary } from '../../services/project.service';

const HEALTH_LABEL: Record<string, string> = { green: 'On track', amber: 'At risk', red: 'Off track' };
const TRIGGER_OPTIONS = ['manual', 'initial', 'change_request'] as const;

/**
 * The "PROJECT CONTROL CENTER" stat-tile row from the Overview tab mockup —
 * calls the one bespoke read endpoint the plan defines for this
 * (`GET /project/{id}/summary`), every number computed live server-side
 * (never a stored/cached rollup, see merry-splashing-whistle.md).
 */
@Component({
  selector: 'attome-project-overview-tab',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TitleCasePipe, FormsModule],
  styleUrls: ['./project-overview-tab.component.css'],
  templateUrl: './project-overview-tab.component.html',
})
export class ProjectOverviewTabComponent implements OnChanges {
  private readonly svc = inject(ProjectService);

  readonly projectId = input.required<string>();
  readonly triggerOptions = TRIGGER_OPTIONS;

  readonly summary = signal<ProjectSummary | null>(null);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  // Capture-baseline inline form state — at most one project's panel is ever
  // open at a time (this component is per-project), so plain signals are enough.
  readonly showCaptureForm = signal(false);
  readonly captureLabel = signal('');
  readonly captureTrigger = signal<string>('manual');
  readonly capturing = signal(false);
  readonly captureError = signal<string | null>(null);
  readonly captureResult = signal<CaptureBaselineResponse | null>(null);

  ngOnChanges(): void { this.load(); }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.getSummary(this.projectId()).subscribe({
      next: s => { this.summary.set(s); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  healthCaption(health: string | null): string {
    if (health == null) return 'No health status recorded yet';
    return HEALTH_LABEL[health] ?? health;
  }

  budgetCaption(s: ProjectSummary): string {
    if (s.budget_amount == null) return 'No budget set';
    return `${this.formatMoney(s.budget_consumed)} / ${this.formatMoney(s.budget_amount)}`;
  }

  formatMoney(value: number | null): string {
    if (value == null) return '—';
    return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(value);
  }

  formatIndex(value: number | null): string {
    return value == null ? '—' : value.toFixed(2);
  }

  formatDate(value: string | null): string {
    if (!value) return '—';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(date);
  }

  scheduleVarianceCaption(days: number | null): string {
    if (days == null) return 'No baseline planned finish to compare against';
    if (days === 0) return 'On the baseline\'s planned finish';
    return days > 0 ? `${days} days ahead of baseline` : `${Math.abs(days)} days behind baseline`;
  }

  scopeVarianceCaption(delta: number | null): string {
    if (delta == null) return '';
    if (delta === 0) return 'No scope change since baseline';
    return delta > 0 ? `${delta} item(s) added since baseline` : `${Math.abs(delta)} item(s) removed since baseline`;
  }

  openCaptureForm(): void {
    this.captureLabel.set('');
    this.captureTrigger.set('manual');
    this.captureError.set(null);
    this.captureResult.set(null);
    this.showCaptureForm.set(true);
  }

  closeCaptureForm(): void {
    this.showCaptureForm.set(false);
  }

  submitCapture(): void {
    const label = this.captureLabel().trim();
    if (!label) {
      this.captureError.set('Label is required.');
      return;
    }
    this.capturing.set(true);
    this.captureError.set(null);
    this.svc.captureBaseline(this.projectId(), { label, trigger: this.captureTrigger() }).subscribe({
      next: res => {
        this.capturing.set(false);
        this.captureResult.set(res);
        this.load(); // refresh the summary so the new baseline's variance/EVM figures show up
      },
      error: (e: ApiError) => { this.capturing.set(false); this.captureError.set(e.message); },
    });
  }
}
