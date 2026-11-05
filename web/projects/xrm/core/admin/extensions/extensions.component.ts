import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  ExtensionAdminService,
  ExtensionLogLine,
  ExtensionRun,
  ExtensionVersion,
} from '../data/services/extension-admin.service';

/**
 * AE2-T4 — the extensions screen: each extension with its newest version's
 * status, and for the chosen one its latest runs (when, which version, how
 * long, how much fuel, the result) with each run's log lines and error.
 * Log lines arrive with secrets masked; they are shown as text, never HTML.
 */
@Component({
  selector: 'xrm-extensions',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../config-admin.css'],
  template: `
    <section class="config-admin" data-extensions>
      <h2>{{ 'extensionsAdmin.title' | translate }}</h2>
      <p class="config-intro">{{ 'extensionsAdmin.intro' | translate }}</p>
      @if (error(); as e) {
        <p class="config-error" role="alert">{{ e }}</p>
      } @else if (loading()) {
        <p class="config-state">{{ 'extensionsAdmin.loading' | translate }}</p>
      } @else if (!extensions().length) {
        <p class="config-state">{{ 'extensionsAdmin.empty' | translate }}</p>
      } @else {
        <div class="table-wrap">
          <table class="config-table">
            <thead>
              <tr>
                <th scope="col">{{ 'extensionsAdmin.name' | translate }}</th>
                <th scope="col">{{ 'extensionsAdmin.version' | translate }}</th>
                <th scope="col">{{ 'extensionsAdmin.status' | translate }}</th>
                <th scope="col"><span class="visually-hidden">{{ 'extensionsAdmin.actions' | translate }}</span></th>
              </tr>
            </thead>
            <tbody>
              @for (ext of extensions(); track ext.name) {
                <tr [attr.data-extension-row]="ext.name">
                  <th scope="row" class="mono">{{ ext.name }}</th>
                  <td>{{ ext.version }}</td>
                  <td>{{ ext.status }}</td>
                  <td>
                    <button type="button" class="config-action" (click)="choose(ext.name)"
                            [attr.aria-pressed]="chosen() === ext.name" [attr.data-show-runs]="ext.name">
                      {{ 'extensionsAdmin.showRuns' | translate }}
                    </button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }

      @if (chosen(); as name) {
        <h3>{{ 'extensionsAdmin.runsOf' | translate: { name } }}</h3>
        @if (runsError(); as e) {
          <p class="config-error" role="alert">{{ e }}</p>
        } @else if (runsLoading()) {
          <p class="config-state">{{ 'extensionsAdmin.loadingRuns' | translate }}</p>
        } @else if (!runs().length) {
          <p class="config-state" data-no-runs>{{ 'extensionsAdmin.noRuns' | translate }}</p>
        } @else {
          <div class="table-wrap">
            <table class="config-table" data-runs>
              <thead>
                <tr>
                  <th scope="col">{{ 'extensionsAdmin.started' | translate }}</th>
                  <th scope="col">{{ 'extensionsAdmin.version' | translate }}</th>
                  <th scope="col">{{ 'extensionsAdmin.duration' | translate }}</th>
                  <th scope="col">{{ 'extensionsAdmin.fuel' | translate }}</th>
                  <th scope="col">{{ 'extensionsAdmin.result' | translate }}</th>
                  <th scope="col"><span class="visually-hidden">{{ 'extensionsAdmin.actions' | translate }}</span></th>
                </tr>
              </thead>
              <tbody>
                @for (run of runs(); track run.id) {
                  <tr [attr.data-run-row]="run.id">
                    <td>{{ when(run.started_at) }}</td>
                    <td>{{ run.version }}</td>
                    <td>{{ 'extensionsAdmin.ms' | translate: { ms: count(run.duration_ms) } }}</td>
                    <td>{{ count(run.fuel_used) }}</td>
                    <td [attr.data-result]="run.ok ? 'ok' : 'failed'">
                      {{ (run.ok ? 'extensionsAdmin.ok' : 'extensionsAdmin.failed') | translate }}
                      @if (run.is_test) {
                        ({{ 'extensionsAdmin.test' | translate }})
                      }
                    </td>
                    <td>
                      <button type="button" class="config-action" (click)="toggle(run.id)"
                              [attr.aria-expanded]="open() === run.id" [attr.data-open-run]="run.id">
                        {{ 'extensionsAdmin.logs' | translate }}
                      </button>
                    </td>
                  </tr>
                  @if (open() === run.id) {
                    <tr data-run-detail>
                      <td colspan="6">
                        @if (run.error) {
                          <p class="config-error mono" data-run-error>{{ run.error }}</p>
                        }
                        @if (lines(run).length) {
                          <ol class="mono" data-run-logs>
                            @for (line of lines(run); track $index) {
                              <li><strong>{{ line.level }}</strong> {{ line.message }}</li>
                            }
                          </ol>
                        } @else {
                          <p class="config-state">{{ 'extensionsAdmin.noLogs' | translate }}</p>
                        }
                      </td>
                    </tr>
                  }
                }
              </tbody>
            </table>
          </div>
        }
      }
    </section>
  `,
})
export class ExtensionsComponent implements OnInit {
  private readonly svc = inject(ExtensionAdminService);
  private readonly lang = inject(LangService);

  private readonly versions = signal<ExtensionVersion[]>([]);
  /** Each extension once, as its newest version (the list is newest first per name). */
  readonly extensions = computed(() => {
    const seen = new Set<string>();
    return this.versions().filter(v => !seen.has(v.name) && seen.add(v.name));
  });
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  readonly chosen = signal<string | null>(null);
  readonly runs = signal<ExtensionRun[]>([]);
  readonly runsLoading = signal(false);
  readonly runsError = signal<string | null>(null);
  /** The run whose logs are shown. */
  readonly open = signal<string | null>(null);

  ngOnInit(): void {
    this.svc.versions().subscribe({
      next: page => {
        this.versions.set(page.items);
        this.error.set(null);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  choose(name: string): void {
    this.chosen.set(name);
    this.open.set(null);
    this.runs.set([]);
    this.runsError.set(null);
    this.runsLoading.set(true);
    this.svc.runs(name).subscribe({
      next: page => {
        // A later choice wins over a slower earlier answer.
        if (this.chosen() !== name) return;
        this.runs.set(page.items);
        this.runsLoading.set(false);
      },
      error: (e: ApiError) => {
        if (this.chosen() !== name) return;
        this.runsError.set(this.lang.errorText(e));
        this.runsLoading.set(false);
      },
    });
  }

  toggle(id: string): void {
    this.open.set(this.open() === id ? null : id);
  }

  /** The run's log lines; anything not shaped as a line is left out. */
  lines(run: ExtensionRun): ExtensionLogLine[] {
    const logs = run.logs as unknown;
    if (!Array.isArray(logs)) return [];
    return logs
      .filter((l): l is ExtensionLogLine =>
        typeof l === 'object' && l !== null && typeof l.level === 'string' && typeof l.message === 'string')
      .map(l => ({ level: l.level, message: l.message }));
  }

  when(iso: string): string {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return iso;
    return new Intl.DateTimeFormat(this.lang.intlLocale(), { dateStyle: 'medium', timeStyle: 'medium' })
      .format(date);
  }

  count(n: number): string {
    return new Intl.NumberFormat(this.lang.intlLocale()).format(n);
  }
}
