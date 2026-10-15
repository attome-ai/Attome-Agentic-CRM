import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `attome_server::deploy_event::DeployEvent`. */
export interface DeployEvent {
  id: string;
  node: string;
  version: string;
  kind: 'start' | 'drain' | 'restart';
  started_by: string | null;
  started_at: string;
  finished_at: string | null;
  failed_requests: number | null;
}

/** Seconds from start to finish, or null while still running. */
export function durationSeconds(event: DeployEvent): number | null {
  if (!event.finished_at) return null;
  const ms = Date.parse(event.finished_at) - Date.parse(event.started_at);
  return Number.isFinite(ms) ? Math.max(0, Math.round(ms / 1000)) : null;
}

/**
 * Deploy history (roadmap AB7-T9): each node's recent starts and drains with
 * version, who started it, how long it took and failed requests; a row with
 * failed requests is highlighted. Logical CSS only.
 */
@Component({
  selector: 'xrm-deploys',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  template: `
    <section class="dp">
      <h3>{{ 'deploysPage.title' | translate }}</h3>
      @if (error(); as message) { <p class="dp-error" role="alert">{{ message }}</p> }
      @if (events().length === 0) {
        <p class="dp-muted">{{ 'deploysPage.none' | translate }}</p>
      } @else {
        <table class="dp-table">
          <thead>
            <tr>
              <th scope="col">{{ 'deploysPage.node' | translate }}</th>
              <th scope="col">{{ 'deploysPage.version' | translate }}</th>
              <th scope="col">{{ 'deploysPage.kind' | translate }}</th>
              <th scope="col">{{ 'deploysPage.startedAt' | translate }}</th>
              <th scope="col">{{ 'deploysPage.duration' | translate }}</th>
              <th scope="col">{{ 'deploysPage.startedBy' | translate }}</th>
              <th scope="col">{{ 'deploysPage.failed' | translate }}</th>
            </tr>
          </thead>
          <tbody>
            @for (e of events(); track e.id) {
              <tr [class.dp-failed]="(e.failed_requests ?? 0) > 0" [attr.data-deploy]="e.id">
                <td dir="ltr">{{ e.node }}</td>
                <td dir="ltr">{{ e.version }}</td>
                <td>{{ 'deploysPage.kinds.' + e.kind | translate }}</td>
                <td>{{ e.started_at | localDate }}</td>
                <td dir="ltr">{{ duration(e) }}</td>
                <td>{{ e.started_by ?? '' }}</td>
                <td dir="ltr">{{ e.failed_requests ?? '' }}</td>
              </tr>
            }
          </tbody>
        </table>
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .dp { display: flex; flex-direction: column; gap: 0.5rem; }
    .dp h3 { margin-block: 0; font-size: 1rem; }
    .dp-table { inline-size: 100%; border-collapse: collapse; font-size: 0.875rem; }
    .dp-table th, .dp-table td { text-align: start; padding-block: 0.25rem; padding-inline: 0.5rem;
      border-block-end: 1px solid var(--color-border); }
    .dp-failed td { background: color-mix(in srgb, var(--color-danger) 12%, transparent); }
    .dp-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .dp-error { color: var(--color-danger); }
  `],
})
export class DeploysComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly events = signal<DeployEvent[]>([]);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.api.get<{ items: DeployEvent[] }>('/api/v1/admin/deploys').subscribe({
      next: page => this.events.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** `12 s`, or an em dash while the step is still running. */
  duration(event: DeployEvent): string {
    const seconds = durationSeconds(event);
    return seconds === null ? '—' : `${seconds} s`;
  }
}
